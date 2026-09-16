/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.user;

import io.helixiam.authorization.domain.ChangePassword;
import io.helixiam.authorization.domain.UserRegister;

import java.util.Map;
import java.util.Set;

public interface UserPublisher {
    String EXCHANGE_AUTHORIZATION_USER = "exchange-authorization-user";
    String AUTHORIZATION_USER_PROFILE_CLAIMS = "authorization.user.profile.claims";
    String AUTHORIZATION_USER_SELF_SIGNUP = "authorization.user.self.signup";
    String AUTHORIZATION_USER_EMAIL_VERIFY = "authorization.user.email.verify";
    String AUTHORIZATION_USER_RESET_PASSWORD = "authorization.user.reset.password";
    String AUTHORIZATION_USER_RESET_PASSWORD_UPDATE = "authorization.user.reset.password.update";
    String AUTHORIZATION_USER_IN_ROLES_GET = "authorization.user.in.roles.get";
    String AUTHORIZATION_USER_ENABLE_MFA = "authorization.user.mfa.enable";

    Map<String, String> getClaimProfile(final String userId);

    UserRegister selfSignup(final UserRegister userRegister);

    Boolean resetPasswordRequest(final String userName);

    Boolean resetPasswordUpdate(final ChangePassword changePassword);

    Boolean verifyEmail(final String code);

    Boolean enableMfa(final String userId);

    Set<String> getUserInRoles(final String userId);
}
