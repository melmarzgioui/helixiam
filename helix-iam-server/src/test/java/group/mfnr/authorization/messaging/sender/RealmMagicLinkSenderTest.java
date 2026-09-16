package group.mfnr.authorization.messaging.sender;

import group.mfnr.authorization.flow.magiclink.MagicLinkMessage;
import group.mfnr.authorization.messaging.MessagingService;
import group.mfnr.authorization.service.UserInfoService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM notifications (N6b): the live magic-link sender renders the realm's {@code magic-link-email}
 * template (with the clickable link, a human TTL, and the user's claims under {@code user.}) and dispatches it
 * through the realm's configured email provider — instead of just logging the link.
 */
class RealmMagicLinkSenderTest {

    private final MessagingService messaging = mock(MessagingService.class);
    private final UserInfoService userInfo = mock(UserInfoService.class);

    @Test
    void rendersMagicLinkTemplateWithLinkTtlAndUserClaims() {
        when(userInfo.getOidcClaimProfile("u1")).thenReturn(Map.of("email", "ada@h.test", "given_name", "Ada"));
        when(messaging.sendEmail(any(), any(), any(), any())).thenReturn(true);
        final RealmMagicLinkSender sender = new RealmMagicLinkSender(messaging, userInfo, 600_000L);

        sender.send(new MagicLinkMessage("u1", "ada@h.test", "https://helix.test/login/magic?token=abc"));

        @SuppressWarnings("unchecked") final ArgumentCaptor<Map<String, String>> vars = ArgumentCaptor.forClass(Map.class);
        verify(messaging).sendEmail(eq("master"), eq("ada@h.test"), eq("magic-link-email"), vars.capture());
        assertThat(vars.getValue())
                .containsEntry("link", "https://helix.test/login/magic?token=abc")
                .containsEntry("ttl", "10 minutes")
                .containsEntry("user.email", "ada@h.test")
                .containsEntry("user.given_name", "Ada");
    }

    @Test
    void doesNotThrow_whenNoEmailProviderConfigured() {
        when(userInfo.getOidcClaimProfile(any())).thenReturn(Map.of());
        when(messaging.sendEmail(any(), any(), any(), any())).thenReturn(false);
        final RealmMagicLinkSender sender = new RealmMagicLinkSender(messaging, userInfo, 600_000L);

        // No provider → sendEmail returns false → falls back to logging, never throws.
        sender.send(new MagicLinkMessage("u1", "ada@h.test", "https://helix.test/magic?token=x"));
    }
}
