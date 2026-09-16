/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.push.PushApproval;
import io.helixiam.authorization.flow.push.PushApprovalService;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

/**
 * Helix IAM E4.3: push-approval factor ("approve on your phone" with number matching). For an
 * already-identified user (2nd factor / step-up), {@link #authenticate} starts an approval (push +
 * number) and renders the view showing the number to match; on the browser's post-back
 * {@link #action} consumes the APPROVED request. The phone resolves it out-of-band (poll-based).
 */
public class PushApprovalAuthenticator implements Authenticator {

    static final String VIEW = "push-form";
    static final String ID_ATTRIBUTE = "push.id";
    static final String NUMBER_ATTRIBUTE = "push.number";

    private final PushApprovalService pushApprovalService;

    public PushApprovalAuthenticator(final PushApprovalService pushApprovalService) {
        this.pushApprovalService = pushApprovalService;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("push", "Push Approval", FactorClass.POSSESSION, 6);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        if (context.userId() == null) {
            context.failure("Push approval requires an identified user");
            return;
        }
        final PushApproval approval = pushApprovalService.start(context.userId());
        context.putAttribute(ID_ATTRIBUTE, approval.id());
        context.putAttribute(NUMBER_ATTRIBUTE, approval.expectedNumber());
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final Object id = context.getAttribute(ID_ATTRIBUTE);
        if (id == null) {
            context.failure("No push approval");
            return;
        }
        final String userId = pushApprovalService.consume(id.toString());
        if (userId != null) {
            context.establishUser(userId);
            context.success();
        } else {
            // Not approved yet (browser polled early) — keep waiting.
            context.challenge(VIEW);
        }
    }
}
