/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Who is acting, declared explicitly by the entry point — never inferred from a URI (security review H5).
 *
 * <ul>
 *   <li>{@link Kind#ADMIN}: an authorised admin-API request; set by {@code AdminAuthorizationManager} where the admin
 *       route is authorised. Its permissions are the authenticated principal's.</li>
 *   <li>{@link Kind#UNPRIVILEGED}: a machine entry point that holds no admin permission (SCIM, dynamic client
 *       registration); set by that controller after it authenticated the caller.</li>
 *   <li>{@link Kind#SELF}: a user acting on their own account (account console, required actions); may act on that
 *       one user only.</li>
 *   <li>{@link Kind#SYSTEM}: genuinely internal work, only through {@link #asSystem} — grep for it to review every
 *       caller (listed in the BYO-keys design doc).</li>
 * </ul>
 * With no actor at all, the guards refuse: nothing is exempt by default.
 */
public record AdminActor(Kind kind, String what, Authentication authentication, String selfUserId) {

    public enum Kind { ADMIN, UNPRIVILEGED, SELF, SYSTEM, DEV_OPEN }

    /** The request attribute an admin entry point stores its actor under. */
    public static final String ATTRIBUTE = AdminActor.class.getName();

    private static final ThreadLocal<AdminActor> OVERRIDE = new ThreadLocal<>();

    @Override
    public String toString() {
        return "AdminActor[" + kind + ", " + what + "]";
    }

    public static AdminActor admin(final Authentication auth) {
        return new AdminActor(Kind.ADMIN, "admin API", auth, null);
    }

    public static AdminActor devOpen() {
        return new AdminActor(Kind.DEV_OPEN, "dev-open admin API", null, null);
    }

    public static AdminActor unprivileged(final String what) {
        return new AdminActor(Kind.UNPRIVILEGED, what, null, null);
    }

    public static AdminActor self(final String userId) {
        return new AdminActor(Kind.SELF, "self-service", null, userId);
    }

    /** Declares the actor of the current request (an entry point, after it authenticated the caller). */
    public static void declare(final AdminActor actor) {
        final RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            attrs.setAttribute(ATTRIBUTE, actor, RequestAttributes.SCOPE_REQUEST);
        }
    }

    /** Runs {@code body} with {@code actor} for this thread (self-service and machine entry points). */
    public static <T> T as(final AdminActor actor, final Supplier<T> body) {
        final AdminActor previous = OVERRIDE.get();
        OVERRIDE.set(actor);
        try {
            return body.get();
        } finally {
            if (previous == null) {
                OVERRIDE.remove();
            } else {
                OVERRIDE.set(previous);
            }
        }
    }

    /**
     * Runs genuinely internal work (bootstrap, migrations, an internal clean-up) unrestricted. {@code why} names the
     * reason; every caller is reviewed (design doc, "asSystem() callers").
     */
    public static <T> T asSystem(final String why, final Supplier<T> body) {
        return as(new AdminActor(Kind.SYSTEM, why, null, null), body);
    }

    /** {@link #asSystem(String, Supplier)} without a result. */
    public static void asSystem(final String why, final Runnable body) {
        asSystem(why, () -> {
            body.run();
            return null;
        });
    }

    /** The current actor: an {@link #as} / {@link #asSystem} scope first, else the request's declared actor. */
    public static Optional<AdminActor> current() {
        final AdminActor override = OVERRIDE.get();
        if (override != null) {
            return Optional.of(override);
        }
        final RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        final Object v = attrs == null ? null : attrs.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        return v instanceof AdminActor a ? Optional.of(a) : Optional.empty();
    }
}
