/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.exception;

import io.helixiam.common.exception.DuplicateException;
import io.helixiam.persistence.DatabaseConstant;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class DatabaseExceptionHandler {
    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    @AfterThrowing(pointcut = "execution(* org.springframework.data.jpa.repository.JpaRepository.*(..))", throwing = "ex")
    public void handleError(final Exception ex) throws Exception {

        if(ex instanceof DataAccessException) {
            LOG.error(ex.getMessage());

            if(ex instanceof DataIntegrityViolationException) {
                throw new DuplicateException("Conflicting record found");
            }

            throw new DatabaseException();
        }

        throw ex;
    }
}
