package io.helixiam.common.exception;

/**
 * Vendored from group.mfnr.subscriber.starter.security.utils (starter-security module).
 * Not in the Task 1 file list; pulled in transitively as Task 2 folded
 * group.mfnr.authorization.service.key.KeyMaterialService, which needs
 * {@link io.helixiam.common.security.RSAKeyReader}. Verbatim (no AMQP/broker dependency in the
 * original).
 */
public class KeyHandlingException extends RuntimeException {

    public KeyHandlingException(final String message) {
        super(message);
    }

}
