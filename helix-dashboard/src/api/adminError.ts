/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A failed admin API call. On a 400 the server answers `{message, fieldErrors}` (AdminValidationAdvice); the field
 * keys are the request's own (`alias`, `displayName`, `config.<key>`, `name`, `privateKeyPem`, ...).
 */
export class AdminApiError extends Error {
  constructor(message: string, readonly status: number, readonly fieldErrors: Record<string, string> = {}) {
    super(message);
    this.name = "AdminApiError";
  }
}

/** The JSON of a successful response (null for 204), or an AdminApiError carrying the server's message and fields. */
export async function adminJson<T = unknown>(res: Response): Promise<T> {
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`.trim();
    let fieldErrors: Record<string, string> = {};
    try {
      const body = await res.json();
      if (body && typeof body.message === "string" && body.message) message = body.message;
      if (body && body.fieldErrors && typeof body.fieldErrors === "object") fieldErrors = body.fieldErrors;
    } catch {
      /* non-JSON error body: keep the status line */
    }
    throw new AdminApiError(message, res.status, fieldErrors);
  }
  return (res.status === 204 ? null : await res.json()) as T;
}
