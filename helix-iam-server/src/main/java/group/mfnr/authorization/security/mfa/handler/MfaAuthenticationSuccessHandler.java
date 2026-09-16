package group.mfnr.authorization.security.mfa.handler;

import group.mfnr.authorization.domain.UserCredentials;
import group.mfnr.authorization.security.mfa.domain.MfaAuthentication;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

public class MfaAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler mfaHandler;
    private final AuthenticationSuccessHandler mfaRegisterHandler;

//    @Autowired
    public MfaAuthenticationSuccessHandler(final String secondAuthUrl, final String register) {
        this.mfaHandler = new SimpleUrlAuthenticationSuccessHandler(secondAuthUrl);
        this.mfaRegisterHandler = new SimpleUrlAuthenticationSuccessHandler(register);
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException, ServletException {

        if (authentication.getPrincipal() instanceof UserCredentials userCredentials) {
            SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(authentication));
            if (userCredentials.isMfaEnabled()) {
                mfaHandler.onAuthenticationSuccess(request, response, authentication);
            } else {
                mfaRegisterHandler.onAuthenticationSuccess(request, response, authentication);
            }
        }
    }
}
