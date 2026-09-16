package io.helixiam.authorization.service.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ConsoleClientBootstrapServiceTest {

  private final ServiceProviderRepository repo = mock(ServiceProviderRepository.class);
  private final ConsoleClientBootstrapService svc =
      new ConsoleClientBootstrapService(repo, "http://localhost:8180");

  @Test
  void createsPublicPkceConsoleClientWhenAbsent() {
    when(repo.findByClientIdAndRealmIdAndDeleted("helix-console", "master", false))
        .thenReturn(Optional.empty());

    svc.ensureConsoleClient("master");

    ArgumentCaptor<ServiceProviderOAuthClient> cap =
        ArgumentCaptor.forClass(ServiceProviderOAuthClient.class);
    verify(repo).save(cap.capture());
    ServiceProviderOAuthClient c = cap.getValue();
    assertThat(c.getClientId()).isEqualTo("helix-console");
    assertThat(c.getRealmId()).isEqualTo("master");
    assertThat(c.getPublicClient()).isTrue();
    assertThat(c.getClientSecret()).isNull();
    assertThat(c.getRedirectUris()).contains("http://localhost:8180/console/callback");
    assertThat(c.getWebOriginSet()).contains("http://localhost:8180");
    assertThat(c.getPostLogoutRedirectUris()).contains("http://localhost:8180/");
    assertThat(c.getScopes()).contains("openid");
    assertThat(c.getAuthorizationGrantTypes())
        .extracting(AuthorizationGrantType::getValue)
        .contains("authorization_code")
        .doesNotContain("urn:ietf:params:oauth:grant-type:device_code");
  }

  @Test
  void reconcilesRedirectUrisWhenClientAlreadyExists() {
    ServiceProviderOAuthClient existing = new ServiceProviderOAuthClient();
    existing.setClientId("helix-console");
    existing.setRealmId("master");
    existing.setRedirectUris("http://old-host/console/callback");
    when(repo.findByClientIdAndRealmIdAndDeleted("helix-console", "master", false))
        .thenReturn(Optional.of(existing));

    svc.ensureConsoleClient("master");

    ArgumentCaptor<ServiceProviderOAuthClient> cap =
        ArgumentCaptor.forClass(ServiceProviderOAuthClient.class);
    verify(repo).save(cap.capture());
    assertThat(cap.getValue().getRedirectUris())
        .contains("http://localhost:8180/console/callback")
        .doesNotContain("http://old-host/console/callback");
  }
}
