import { createHash } from "node:crypto";
import type { ProviderQuota } from "../types.js";

// The stamp follows this reading through object spreads without entering JSON,
// TOON, or other serialized output. It never re-reads a mutable credential file.
const ZAI_READING_CONTEXT = Symbol("zaiReadingContext");
type ZaiStampedQuota = ProviderQuota & { [ZAI_READING_CONTEXT]?: string };

export function stampZaiReadingContext(
  provider: ProviderQuota,
  contextId: string,
): ProviderQuota {
  (provider as ZaiStampedQuota)[ZAI_READING_CONTEXT] = contextId;
  return provider;
}

export function zaiReadingContextId(
  provider: ProviderQuota,
): string | undefined {
  return (provider as ZaiStampedQuota)[ZAI_READING_CONTEXT];
}

// A key, rather than its file or source name, identifies the account. The same
// key can answer through either store, while a rotated key cannot inherit quota.
export function zaiCacheContextId(credential: string): string {
  return createHash("sha256")
    .update(`zai-credential-v1\0${credential}`)
    .digest("hex");
}
