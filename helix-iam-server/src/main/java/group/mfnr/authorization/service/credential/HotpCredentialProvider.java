package group.mfnr.authorization.service.credential;

import group.mfnr.authorization.service.mfa.HotpService;
import org.springframework.stereotype.Component;

/** Helix IAM E3.4: HOTP as an auto-discovered {@link CredentialProvider}. */
@Component
public class HotpCredentialProvider implements CredentialProvider {

    private final HotpService hotpService;

    public HotpCredentialProvider(final HotpService hotpService) {
        this.hotpService = hotpService;
    }

    @Override
    public String type() {
        return "hotp";
    }

    @Override
    public boolean verify(final String userId, final String input) {
        return hotpService.verify(userId, input);
    }
}
