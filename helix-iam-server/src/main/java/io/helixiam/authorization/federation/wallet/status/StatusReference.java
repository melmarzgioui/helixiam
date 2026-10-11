/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

/** A credential's pointer into a Token Status List: the bit index and the list's URI. */
public record StatusReference(int idx, String uri) {}
