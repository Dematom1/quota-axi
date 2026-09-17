import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { providerFetch } from "../lib/http.js";
import { usableLiteralSecret } from "../lib/secret.js";
import {
  clampPercent,
  nowIso,
  percentRemaining,
  retryAfterToIso,
} from "../lib/time.js";
import type {
  AuthProviderReport,
  AuthSourceReport,
  ProviderAdapter,
  ProviderOptions,
  ProviderQuota,
  QuotaWindow,
  SourceAttempt,
} from "../types.js";
import {
  failedProvider,
  sourceNames,
  statusFromError,
  successProvider,
} from "./common.js";
import {
  type AttemptOutcome,
  selectCredential,
} from "./credential-selection.js";

const LABEL = "Fireworks AI";
const API_BASE = "https://api.fireworks.ai";
const API_TIMEOUT_MS = 15_000;
/** The vendor caps `pageSize` at 200; an account's quota list is far smaller. */
const QUOTA_PAGE_SIZE = 200;
const AUTH_INI_MAX_BYTES = 65_536;

const ENV_API_KEY = "FIREWORKS_API_KEY";
const ENV_ACCOUNT_ID = "FIREWORKS_ACCOUNT_ID";
const ENV_AUTH_INI = "FIREWORKS_AUTH_INI";
const ENV_SOURCE = "env";
const AUTH_INI_SOURCE = "fireworks:auth.ini";

/**
 * Fireworks' credential stores in ownership-stability order.
 *
 * `FIREWORKS_API_KEY` wins because the vendor's own SDKs resolve it before
 * opening any store, so it names the key a live session uses; it has no expiry
 * and no refresh token, so it is never rotated or persisted. `auth.ini` is the
 * store `firectl set-api-key`/`firectl signin` writes and is consulted only
 * when the environment holds nothing usable.
 */
const FIREWORKS_SOURCE_ORDER = [ENV_SOURCE, AUTH_INI_SOURCE] as const;

type FireworksSource = (typeof FIREWORKS_SOURCE_ORDER)[number];

/**
 * `auth.ini` also holds SSO material (`id_token`, `refresh_token`,
 * `client_id`, `cognito_domain`, `issuer_url`). Only these two keys are ever
 * read out of it, so nothing else is held in memory at all.
 */
const AUTH_INI_KEYS = ["api_key", "account_id"] as const;

/** Fireworks account ids are path segments; anything else never reaches a URL. */
const ACCOUNT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export type FireworksCredential = {
  apiKey: string;
  /**
   * Configured alongside the key in the same source. Halves never cross
   * sources: pairing one store's key with another's account would query an
   * account the key was never issued for.
   */
  accountId?: string;
};

/** One store's local reading, before any request. */
export type FireworksResolution =
  | {
      status: "resolved";
      credential: FireworksCredential;
      report: AuthSourceReport;
    }
  | {
      status: "absent" | "structurally_invalid" | "read_error";
      report: AuthSourceReport;
    };

export type NormalizedFireworksQuotas = {
  windows: QuotaWindow[];
  /** Declared quotas that carry no usable ratio, so they bound nothing. */
  untrustedWindowIds: string[];
};

type Dependencies = {
  resolve(source: FireworksSource): FireworksResolution;
  fetch: typeof providerFetch;
  now: () => string;
  timeoutMs: number;
};

export function fireworksAuthIniPath(): string {
  return (
    process.env[ENV_AUTH_INI]?.trim() ||
    join(homedir(), ".fireworks", "auth.ini")
  );
}

export function createFireworksAdapter(
  overrides: Partial<Dependencies> = {},
): ProviderAdapter {
  const dependencies: Dependencies = {
    resolve: resolveFireworksCredential,
    fetch: providerFetch,
    now: nowIso,
    timeoutMs: API_TIMEOUT_MS,
    ...overrides,
  };
  return {
    id: "fireworks",
    label: LABEL,
    fetchQuota: (_options: ProviderOptions) => fetchQuota(dependencies),
    inspectAuth: (_options: ProviderOptions) => inspectAuth(dependencies),
  };
}

export const fireworksAdapter = createFireworksAdapter();

async function fetchQuota(dependencies: Dependencies): Promise<ProviderQuota> {
  const attempts: SourceAttempt[] = [];
  let failure: FireworksFailure | undefined;
  let liveWithoutQuota = false;

  for (const source of FIREWORKS_SOURCE_ORDER) {
    const resolution = dependencies.resolve(source);
    if (resolution.status !== "resolved") {
      attempts.push(unavailableAttempt(source, resolution.status));
      if (resolution.status === "read_error")
        failure = { error: "credential_resolution_failed" };
      continue;
    }

    attempts.push({ source, status: "failed" });
    const selection = await selectCredential(
      [{ source, localState: "valid", credential: resolution.credential }],
      (candidate) => readQuotas(candidate.credential, dependencies),
    );

    const quota = selection.result;
    if (selection.outcome === "quota" && quota) {
      attempts[attempts.length - 1] = { source, status: "success" };
      return withUntrusted(
        successProvider({
          provider: "fireworks",
          label: LABEL,
          source: "api",
          windows: quota.windows,
          refreshedAt: dependencies.now(),
          sourcesTried: sourceNames(attempts),
          attempts,
        }),
        quota.untrustedWindowIds,
      );
    }

    if (selection.outcome === "live_no_quota") {
      // The key was accepted and the quota operation refused: a permission
      // boundary, never a sign-out.
      liveWithoutQuota = true;
      attempts[attempts.length - 1] = {
        source,
        status: "failed",
        error: FORBIDDEN_ERROR,
      };
      continue;
    }

    if (selection.outcome === "all_rejected") {
      attempts[attempts.length - 1] = {
        source,
        status: "failed",
        error: AUTH_REJECTED_ERROR,
      };
      continue;
    }

    const error = selection.transientError ?? "quota_request_failed";
    attempts[attempts.length - 1] = { source, status: "failed", error };
    failure = { error, retryAfter: selection.retryAfter };
    break;
  }

  if (failure) {
    return failedProvider({
      provider: "fireworks",
      label: LABEL,
      // A rate limit stays a rate limit whether or not the vendor sent a
      // `Retry-After`; every other failure here is a failed read.
      status: statusFromError(failure.error),
      error: failure.error,
      retryAfter: failure.retryAfter,
      source: "api",
      sourcesTried: sourceNames(attempts),
      attempts,
    });
  }

  if (liveWithoutQuota) {
    return withAuthStatus(
      failedProvider({
        provider: "fireworks",
        label: LABEL,
        status: "unavailable",
        error: FORBIDDEN_ERROR,
        source: "api",
        sourcesTried: sourceNames(attempts),
        attempts,
      }),
      "usable",
    );
  }

  return failedProvider({
    provider: "fireworks",
    label: LABEL,
    status: "auth_required",
    error: definingCredentialError(attempts),
    source: "api",
    sourcesTried: sourceNames(attempts),
    attempts,
  });
}

async function inspectAuth(
  dependencies: Dependencies,
): Promise<AuthProviderReport> {
  return {
    provider: "fireworks",
    sources: FIREWORKS_SOURCE_ORDER.map(
      (source) => dependencies.resolve(source).report,
    ),
  };
}

/**
 * A store that holds nothing is absent, never degraded; one that holds an
 * unusable value stays visible as a credential that exists.
 */
function unavailableAttempt(
  source: FireworksSource,
  status: Exclude<FireworksResolution["status"], "resolved">,
): SourceAttempt {
  if (status === "absent")
    return { source, status: "skipped", error: "credentials_missing" };
  if (status === "read_error")
    return {
      source,
      status: "skipped",
      error: "credential_resolution_failed",
      degraded: true,
    };
  return {
    source,
    status: "skipped",
    error: "credentials_invalid",
    credentialPresent: true,
  };
}

function definingCredentialError(attempts: SourceAttempt[]): string {
  if (attempts.some((attempt) => attempt.error === AUTH_REJECTED_ERROR))
    return AUTH_REJECTED_ERROR;
  return attempts.some((attempt) => attempt.credentialPresent)
    ? "fireworks_credential_invalid"
    : "fireworks_credential_unavailable";
}

function withUntrusted(
  provider: ProviderQuota,
  untrustedWindowIds: string[],
): ProviderQuota {
  if (untrustedWindowIds.length === 0) return provider;
  return {
    ...provider,
    state: { ...provider.state, untrustedWindowIds },
  };
}

function withAuthStatus(
  provider: ProviderQuota,
  authStatus: ProviderQuota["state"]["authStatus"],
): ProviderQuota {
  return { ...provider, state: { ...provider.state, authStatus } };
}

// ---------------------------------------------------------------------------
// Local resolution
// ---------------------------------------------------------------------------

export function resolveFireworksCredential(
  source: FireworksSource,
): FireworksResolution {
  return source === ENV_SOURCE ? resolveFromEnv() : resolveFireworksAuthIni();
}

function resolveFromEnv(): FireworksResolution {
  const raw = process.env[ENV_API_KEY];
  // A blank value selects nothing and preserves the stored path.
  if (raw === undefined || raw.trim() === "")
    return { status: "absent", report: envReport("missing") };
  const apiKey = usableLiteralSecret(raw);
  if (!apiKey)
    return {
      status: "structurally_invalid",
      report: envReport("invalid", "credentials_invalid"),
    };
  const account = accountIdValue(process.env[ENV_ACCOUNT_ID]);
  if (account.status === "invalid")
    return {
      status: "structurally_invalid",
      report: envReport("invalid", "account_id_invalid"),
    };
  return {
    status: "resolved",
    credential: {
      apiKey,
      ...(account.value ? { accountId: account.value } : {}),
    },
    report: envReport("available"),
  };
}

function envReport(
  status: AuthSourceReport["status"],
  error?: string,
): AuthSourceReport {
  return {
    source: ENV_SOURCE,
    path: `$${ENV_API_KEY}`,
    status,
    ...(error ? { error, credentialPresent: true } : {}),
  };
}

export function resolveFireworksAuthIni(
  path = fireworksAuthIniPath(),
): FireworksResolution {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errorCode(error) === "ENOENT")
      return {
        status: "absent",
        report: { source: AUTH_INI_SOURCE, path, status: "missing" },
      };
    return {
      status: "read_error",
      report: {
        source: AUTH_INI_SOURCE,
        path,
        status: "error",
        error: "file_read_error",
      },
    };
  }
  if (text.length > AUTH_INI_MAX_BYTES)
    return {
      status: "read_error",
      report: {
        source: AUTH_INI_SOURCE,
        path,
        status: "error",
        error: "file_too_large",
      },
    };

  const entries = parseFireworksAuthIni(text);
  const declared = entries.api_key;
  // A blank value selects nothing, exactly as a blank environment key does.
  if (declared === undefined || declared.trim() === "")
    return {
      status: "absent",
      report: { source: AUTH_INI_SOURCE, path, status: "missing" },
    };
  const apiKey = usableLiteralSecret(declared);
  if (!apiKey) return invalidAuthIni(path, "credentials_invalid");
  const account = accountIdValue(entries.account_id);
  if (account.status === "invalid")
    return invalidAuthIni(path, "account_id_invalid");
  return {
    status: "resolved",
    credential: {
      apiKey,
      ...(account.value ? { accountId: account.value } : {}),
    },
    report: { source: AUTH_INI_SOURCE, path, status: "available" },
  };
}

function invalidAuthIni(path: string, error: string): FireworksResolution {
  return {
    status: "structurally_invalid",
    report: {
      source: AUTH_INI_SOURCE,
      path,
      status: "invalid",
      error,
      credentialPresent: true,
    },
  };
}

/**
 * `auth.ini` is written as bare `key = value` lines, and some tooling wraps
 * them in a section header. A narrow walker reads both shapes and keeps only
 * the whitelisted keys, so the SSO tokens in the same file are never held.
 * The first occurrence of a key wins, matching the vendor SDK's own
 * first-match read.
 *
 * @param text raw `auth.ini` contents
 * @returns the whitelisted keys that were present
 */
export function parseFireworksAuthIni(
  text: string,
): Partial<Record<(typeof AUTH_INI_KEYS)[number], string>> {
  const entries: Partial<Record<(typeof AUTH_INI_KEYS)[number], string>> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";"))
      continue;
    if (trimmed.startsWith("[")) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 0) continue;
    const key = trimmed.slice(0, separator).trim().toLowerCase();
    if (!isAuthIniKey(key) || entries[key] !== undefined) continue;
    entries[key] = unquote(trimmed.slice(separator + 1).trim());
  }
  return entries;
}

function isAuthIniKey(key: string): key is (typeof AUTH_INI_KEYS)[number] {
  return (AUTH_INI_KEYS as readonly string[]).includes(key);
}

function unquote(value: string): string {
  const quoted =
    value.length >= 2 &&
    (value.startsWith('"') || value.startsWith("'")) &&
    value.endsWith(value[0]!);
  return quoted ? value.slice(1, -1) : value;
}

function accountIdValue(
  raw: string | undefined,
): { status: "ok"; value?: string } | { status: "invalid" } {
  const trimmed = raw?.trim();
  if (!trimmed) return { status: "ok" };
  return ACCOUNT_ID.test(trimmed)
    ? { status: "ok", value: trimmed }
    : { status: "invalid" };
}

// ---------------------------------------------------------------------------
// Bounded read-only probe
// ---------------------------------------------------------------------------

async function readQuotas(
  credential: FireworksCredential,
  dependencies: Dependencies,
): Promise<AttemptOutcome<NormalizedFireworksQuotas>> {
  try {
    const accountId =
      credential.accountId ??
      (await discoverAccountId(credential, dependencies));
    const payload = await requestJson(
      `/v1/accounts/${encodeURIComponent(accountId)}/quotas?pageSize=${QUOTA_PAGE_SIZE}`,
      credential.apiKey,
      dependencies,
    );
    if (stringValue(objectValue(payload)?.nextPageToken))
      throw new Error("fireworks_quota_incomplete");
    return { kind: "quota", result: normalizeFireworksQuotas(payload) };
  } catch (error) {
    if (error instanceof AuthRejected)
      return { kind: "rejected", error: error.message };
    if (error instanceof PermissionDenied) return { kind: "live_no_quota" };
    return {
      kind: "transient",
      error: error instanceof Error ? error.message : "quota_request_failed",
      ...(error instanceof RateLimited ? { retryAfter: error.retryAfter } : {}),
    };
  }
}

/**
 * A key alone does not name its account, and the account id is a path segment
 * of the quota URL. When no store configured one, the vendor's own account
 * listing resolves it; an ambiguous or empty listing is reported rather than
 * guessed, because reading the wrong account would report another account's
 * numbers as this one's.
 */
async function discoverAccountId(
  credential: FireworksCredential,
  dependencies: Dependencies,
): Promise<string> {
  const payload = await requestJson(
    "/v1/accounts?pageSize=2",
    credential.apiKey,
    dependencies,
  );
  const root = objectValue(payload);
  const listed = root?.accounts;
  if (
    !Array.isArray(listed) ||
    stringValue(root?.nextPageToken) ||
    (root?.totalSize !== undefined && numberValue(root.totalSize) !== 1)
  )
    throw new Error(ACCOUNT_UNRESOLVED_ERROR);
  const names = listed.map((entry) =>
    accountIdFromResourceName(stringValue(objectValue(entry)?.name)),
  );
  const unique = [...new Set(names)];
  if (names.includes(undefined) || unique.length !== 1)
    throw new Error(ACCOUNT_UNRESOLVED_ERROR);
  return unique[0]!;
}

async function requestJson(
  path: string,
  apiKey: string,
  dependencies: Dependencies,
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), dependencies.timeoutMs);
  try {
    const response = await dependencies.fetch(`${API_BASE}${path}`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${apiKey}`,
        accept: "application/json",
      },
      credentials: "omit",
      redirect: "manual",
      signal: controller.signal,
    });
    rejectUnusableResponse(response);
    try {
      return await response.json();
    } catch {
      throw new Error("malformed_json");
    }
  } catch (error) {
    if (controller.signal.aborted)
      throw new Error("provider_timeout", { cause: error });
    if (
      error instanceof AuthRejected ||
      error instanceof PermissionDenied ||
      error instanceof RateLimited
    )
      throw error;
    if (error instanceof Error && KNOWN_REQUEST_ERRORS.has(error.message))
      throw error;
    throw new Error("network_unavailable", { cause: error });
  } finally {
    clearTimeout(timer);
  }
}

function rejectUnusableResponse(response: Response): void {
  const status = response.status;
  if (status === 200) return;
  // 401 is an unauthenticated key. 403 means the caller was identified and the
  // operation refused, which is a permission boundary rather than a sign-out.
  if (status === 401) throw new AuthRejected();
  if (status === 403) throw new PermissionDenied();
  if (status === 429)
    throw new RateLimited(retryAfterToIso(response.headers.get("retry-after")));
  if (status >= 300 && status <= 399) throw new Error("redirect_rejected");
  if (status >= 500) throw new Error("provider_unavailable");
  throw new Error("provider_request_rejected");
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/**
 * Map the vendor's quota list onto quota windows.
 *
 * Each entry reports the enforced `value`, the approved `maxValue`, and the
 * current `usage`, and carries no cycle at all, so every window is `unknown`
 * kind with no reset. A quota whose usage cannot be expressed as a ratio of
 * its own enforced value bounds nothing, so it is named as untrusted instead
 * of becoming a window with an invented percentage.
 *
 * @param raw decoded `ListQuotas` response
 * @returns windows plus the ids of declared quotas that carry no usable ratio
 */
export function normalizeFireworksQuotas(
  raw: unknown,
): NormalizedFireworksQuotas {
  const root = objectValue(raw);
  const quotas = root?.quotas;
  if (quotas === undefined || quotas === null)
    return { windows: [], untrustedWindowIds: [] };
  if (!Array.isArray(quotas)) throw new Error("schema_invalid");

  const windows: QuotaWindow[] = [];
  const untrustedWindowIds: string[] = [];
  const seen = new Set<string>();
  for (const [offset, entry] of quotas.entries()) {
    const record = objectValue(entry);
    const named = quotaIdFromResourceName(stringValue(record?.name));
    // A nameless or repeated quota still exists; it falls back to its position
    // so one entry can never overwrite another's reading.
    const usable = named !== undefined && !seen.has(`quota:${named}`);
    const label = usable ? named : `quota ${offset + 1}`;
    const id = `quota:${usable ? named : offset + 1}`;
    seen.add(id);
    const percentUsed = quotaPercentUsed(record);
    if (percentUsed === undefined) {
      untrustedWindowIds.push(id);
      continue;
    }
    windows.push({
      id,
      label,
      kind: "unknown",
      percentUsed,
      percentRemaining: percentRemaining(percentUsed),
    });
  }
  return { windows, untrustedWindowIds };
}

function quotaPercentUsed(
  record: Record<string, unknown> | undefined,
): number | undefined {
  if (!record) return undefined;
  const value = numberValue(record.value);
  const usage = numberValue(record.usage);
  if (value === undefined || usage === undefined) return undefined;
  if (!(value > 0) || usage < 0) return undefined;
  return clampPercent((usage / value) * 100);
}

/** `accounts/<account>/quotas/<quota>` -> `<quota>`. */
function quotaIdFromResourceName(name: string | undefined): string | undefined {
  const segment = name?.split("/").pop()?.trim();
  return segment ? segment : undefined;
}

/** `accounts/<account>` -> `<account>`. */
function accountIdFromResourceName(
  name: string | undefined,
): string | undefined {
  const segment = name?.split("/").pop()?.trim();
  return segment && ACCOUNT_ID.test(segment) ? segment : undefined;
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

const AUTH_REJECTED_ERROR = "provider_auth_rejected";
const FORBIDDEN_ERROR = "fireworks_quota_forbidden";
const ACCOUNT_UNRESOLVED_ERROR = "fireworks_account_unresolved";

/** Failures `requestJson` itself raises; anything else is transport trouble. */
const KNOWN_REQUEST_ERRORS = new Set([
  "malformed_json",
  "redirect_rejected",
  "provider_unavailable",
  "provider_request_rejected",
]);

type FireworksFailure = { error: string; retryAfter?: string };

/** A first-party 401: the only probe outcome that is a sign-out verdict. */
class AuthRejected extends Error {
  constructor() {
    super(AUTH_REJECTED_ERROR);
  }
}

/** A first-party 403: the key is live, the quota operation is not permitted. */
class PermissionDenied extends Error {
  constructor() {
    super(FORBIDDEN_ERROR);
  }
}

class RateLimited extends Error {
  constructor(readonly retryAfter: string | undefined) {
    super("provider_rate_limited");
  }
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/** Proto-JSON encodes `int64` as a string, so both shapes are numbers here. */
function numberValue(value: unknown): number | undefined {
  if (typeof value === "number")
    return Number.isFinite(value) ? value : undefined;
  if (typeof value !== "string" || value.trim() === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function errorCode(error: unknown): string | undefined {
  return error &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
    ? error.code
    : undefined;
}
