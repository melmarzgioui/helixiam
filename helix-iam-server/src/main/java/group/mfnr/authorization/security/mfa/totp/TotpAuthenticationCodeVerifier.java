package group.mfnr.authorization.security.mfa.totp;

import group.mfnr.authorization.domain.UserCredentials;
import group.mfnr.authorization.security.mfa.MfaAuthenticationCodeVerifier;
import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;

public class TotpAuthenticationCodeVerifier implements MfaAuthenticationCodeVerifier {
    @Override
    public boolean verify(final UserCredentials userCredentials, final String code) {
        try {
            return TimeBasedOneTimePasswordUtil.validateCurrentNumber(userCredentials.getMfaSecret(), StringUtils.hasText(code) ? Integer.parseInt(code) : 0, 10000);
        } catch (final NumberFormatException | GeneralSecurityException e) {
            return false;
        }
    }
}
