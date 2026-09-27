/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * B1: marks a controller of the signed-in account console ({@code /realms/{realm}/account}). Its pages get the return
 * link in the model and are held behind the second factor, like {@code /oauth2/authorize}
 * ({@link AccountConsoleWebConfig}).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface AccountConsolePage {
}
