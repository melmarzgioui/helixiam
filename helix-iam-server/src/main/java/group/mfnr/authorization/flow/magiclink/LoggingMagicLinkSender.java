package group.mfnr.authorization.flow.magiclink;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helix IAM: dev default {@link MagicLinkSender} — logs the magic link instead of emailing it, so
 * passwordless login is exercisable without an email gateway. A real SMTP adapter replaces it
 * ({@code @ConditionalOnMissingBean}).
 */
public class LoggingMagicLinkSender implements MagicLinkSender {

    private static final Logger LOG = LogManager.getLogger(LoggingMagicLinkSender.class);

    @Override
    public void send(final MagicLinkMessage message) {
        LOG.info("[DEV MAGIC-LINK] for user {} <{}>: {}", message.userId(), message.email(), message.link());
    }
}
