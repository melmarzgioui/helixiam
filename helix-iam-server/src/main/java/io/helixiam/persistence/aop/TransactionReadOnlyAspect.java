package io.helixiam.persistence.aop;

import io.helixiam.persistence.DatabaseConstant;
import io.helixiam.persistence.config.DatabaseEnvironment;
import io.helixiam.persistence.context.DatabaseContextHolder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Order(0)
public class TransactionReadOnlyAspect {

    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    @Around("@annotation(readOnlyDatasource)")
    public Object proceed(final ProceedingJoinPoint proceedingJoinPoint, final ReadOnlyDatasource readOnlyDatasource) throws Throwable {
        try {

            LOG.trace("Execute readonly call '{}'", proceedingJoinPoint.getSignature().getName());
            DatabaseContextHolder.set(DatabaseEnvironment.READONLY);

            return proceedingJoinPoint.proceed();
        } finally {
            DatabaseContextHolder.remove();
            DatabaseContextHolder.reset();
        }
    }
}
