package group.mfnr.authorization.flow.authenticators;

import group.mfnr.authorization.flow.qr.QrLoginService;
import group.mfnr.authorization.flow.qr.QrSession;
import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.Authenticator;
import group.mfnr.authorization.flow.spi.AuthenticatorMetadata;
import group.mfnr.authorization.flow.spi.FactorClass;

/**
 * Helix IAM E4.2: cross-device QR-login factor (passwordless 1st factor or step-up).
 * {@link #authenticate} opens a {@link QrSession} and renders the QR view (the page shows
 * {@code helix://qr-login/{id}?t={token}} and watches status via SSE/poll). When the enrolled phone
 * confirms, the browser posts back and {@link #action} consumes the CONFIRMED session, establishing
 * the bound user. The session id is stashed server-side (never given to the phone for consume), so
 * only the initiating browser can complete the login.
 */
public class QrLoginAuthenticator implements Authenticator {

    static final String VIEW = "qr-login-form";
    static final String SESSION_ATTRIBUTE = "qr.session";
    static final String TOKEN_ATTRIBUTE = "qr.token";

    private final QrLoginService qrLoginService;

    public QrLoginAuthenticator(final QrLoginService qrLoginService) {
        this.qrLoginService = qrLoginService;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("qr-login", "QR Code Login", FactorClass.POSSESSION, 5);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final QrSession session = qrLoginService.open();
        context.putAttribute(SESSION_ATTRIBUTE, session.id());
        context.putAttribute(TOKEN_ATTRIBUTE, session.currentToken());
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final Object sessionId = context.getAttribute(SESSION_ATTRIBUTE);
        if (sessionId == null) {
            context.failure("No QR session");
            return;
        }
        final String userId = qrLoginService.consume(sessionId.toString());
        if (userId != null) {
            context.establishUser(userId);
            context.success();
        } else {
            // Not confirmed yet (the browser posted early or is polling) — keep waiting.
            context.challenge(VIEW);
        }
    }
}
