package group.mfnr.authorization.flow.magiclink;

/**
 * Helix IAM: transport seam for delivering a passwordless {@link MagicLinkMessage} — an SMTP/email
 * adapter in production. The dev default {@link LoggingMagicLinkSender} logs the link so the flow is
 * exercisable without an email gateway (mirrors the OtpSender seam in E3.1).
 */
@FunctionalInterface
public interface MagicLinkSender {

    void send(MagicLinkMessage message);
}
