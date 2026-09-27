/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Bounced email addresses on users (email delivery stage 2): the admin user API reports `emailBounced` while mail to
// the user's current address bounced permanently, and `emailBouncedAt` (epoch millis). The server clears both when
// the address changes or is verified again. Pure helper, unit-tested in userBounce.test.ts.

import type { UserSummary } from "../api/users";
import { absoluteTime } from "../api/datetime";
import type { Locale } from "../i18n/dictionaries";

export interface EmailBounce {
  /** When the address bounced, formatted for the locale; null when the server gave no time. */
  when: string | null;
}

/** The user's bounce state for display, or null when their current address has not bounced. */
export function emailBounce(user: Pick<UserSummary, "emailBounced" | "emailBouncedAt">, locale: Locale = "en"): EmailBounce | null {
  if (!user.emailBounced) return null;
  const at = user.emailBouncedAt;
  if (at == null || !Number.isFinite(at) || at <= 0) return { when: null };
  return { when: absoluteTime(new Date(at).toISOString(), locale) };
}
