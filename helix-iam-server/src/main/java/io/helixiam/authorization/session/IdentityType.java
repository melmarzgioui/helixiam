/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

/** The kind of identity behind a session/token, surfaced on the admin Sessions screen. */
public enum IdentityType {
  USER,
  AGENT,
  SERVICE_ACCOUNT,
  WORKLOAD
}
