package group.mfnr.authorization.idp.ciba;

import group.mfnr.authorization.flow.push.PushApproval;
import group.mfnr.authorization.flow.push.PushApprovalService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E7.5: CIBA backchannel auth orchestrates the E4.3 device push — a request starts a push
 * and yields an auth_req_id; polling maps the push approval state to pending → approved(user), and a
 * client may only poll its own request.
 */
class CibaBackchannelServiceTest {

    private final PushApprovalService push = mock(PushApprovalService.class);
    private final CibaBackchannelService ciba = new CibaBackchannelService(push, () -> "auth-req-1");

    private static PushApproval approval() {
        return new PushApproval("push-1", "user-1", 42, "challenge", 0L, 120_000L);
    }

    @Test
    void requestStartsAPushAndReturnsAnAuthReqId() {
        when(push.start("user-1")).thenReturn(approval());

        final CibaBackchannelService.AuthResponse response =
                ciba.requestAuthentication("client-a", "user-1", "openid", "Approve €10 payment");

        assertThat(response.authReqId()).isEqualTo("auth-req-1");
        assertThat(response.intervalSeconds()).isEqualTo(5);
        assertThat(response.expiresInSeconds()).isEqualTo(120);
    }

    @Test
    void pollIsPendingUntilTheUserApprovesOnTheDeviceThenReturnsTheUser() {
        when(push.start("user-1")).thenReturn(approval());
        ciba.requestAuthentication("client-a", "user-1", "openid", "msg");

        when(push.status("push-1")).thenReturn("PENDING");
        assertThat(ciba.poll("auth-req-1", "client-a").status())
                .isEqualTo(CibaBackchannelService.PollStatus.PENDING);

        when(push.status("push-1")).thenReturn("APPROVED");
        final CibaBackchannelService.PollResult approved = ciba.poll("auth-req-1", "client-a");
        assertThat(approved.status()).isEqualTo(CibaBackchannelService.PollStatus.APPROVED);
        assertThat(approved.userId()).isEqualTo("user-1");
    }

    @Test
    void aDeniedPushSurfacesAsDenied() {
        when(push.start("user-1")).thenReturn(approval());
        ciba.requestAuthentication("client-a", "user-1", "openid", "msg");
        when(push.status("push-1")).thenReturn("DENIED");

        assertThat(ciba.poll("auth-req-1", "client-a").status())
                .isEqualTo(CibaBackchannelService.PollStatus.DENIED);
    }

    @Test
    void aClientCannotPollAnotherClientsRequest() {
        when(push.start("user-1")).thenReturn(approval());
        ciba.requestAuthentication("client-a", "user-1", "openid", "msg");

        assertThatThrownBy(() -> ciba.poll("auth-req-1", "attacker-client"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void anUnknownAuthReqIdIsRejected() {
        assertThatThrownBy(() -> ciba.poll("nope", "client-a")).isInstanceOf(IllegalArgumentException.class);
    }
}
