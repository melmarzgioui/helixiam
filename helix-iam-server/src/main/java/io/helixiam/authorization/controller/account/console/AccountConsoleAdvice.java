/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.account.AccountReferrer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * B1: the account console's return link. {@code ?referrer=<client_id>&referrer_uri=<url>} on any console page is
 * validated ({@link AccountReferrer}) and kept in the session for this realm, so every page of the visit shows
 * "Back to &lt;app&gt;"; values that do not check out are ignored and forget an earlier link.
 */
@ControllerAdvice(annotations = AccountConsolePage.class)
public class AccountConsoleAdvice {

    static final String REFERRER_ATTRIBUTE = "HELIX_ACCOUNT_REFERRER:";

    private final AccountReferrer referrers;

    public AccountConsoleAdvice(final AccountReferrer referrers) {
        this.referrers = referrers;
    }

    /** The validated return link of this visit, or null. */
    @ModelAttribute("referrer")
    public AccountReferrer.Link referrer(final HttpServletRequest request) {
        final String clientId = request.getParameter("referrer");
        final String uri = request.getParameter("referrer_uri");
        if (clientId == null && uri == null) {
            return current(request);
        }
        final AccountReferrer.Link link = referrers.resolve(clientId, uri).orElse(null);
        final HttpSession session = request.getSession(link != null);
        if (session != null) {
            if (link == null) {
                session.removeAttribute(key());
            } else {
                session.setAttribute(key(), link);
            }
        }
        return link;
    }

    /** The return link stored for the current realm, or null (also read by pages rendered after a sign-out). */
    public static AccountReferrer.Link current(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(key()) instanceof AccountReferrer.Link link ? link : null;
    }

    private static String key() {
        return REFERRER_ATTRIBUTE + RealmContextHolder.get();
    }
}
