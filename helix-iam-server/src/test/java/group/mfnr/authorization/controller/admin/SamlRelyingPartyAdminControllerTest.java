package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import group.mfnr.authorization.controller.admin.SamlRelyingPartyAdminController.ImportMetadataRequest;
import group.mfnr.authorization.controller.admin.SamlRelyingPartyAdminController.ImportMetadataUrlRequest;
import group.mfnr.authorization.idp.saml.SamlSpMetadataParser;
import group.mfnr.authorization.idp.saml.SamlSpMetadataParser.ParsedSp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the SAML "import metadata" onboarding endpoints must return a 400 with a friendly
 * {@code {"message":...}} body (never a thrown exception, which would route through the security-guarded
 * /error dispatch). These exercise the controller directly with a mocked publisher + parser.
 */
class SamlRelyingPartyAdminControllerTest {

    private SamlRelyingPartyConfigPublisher publisher;
    private SamlSpMetadataParser metadataParser;
    private SamlRelyingPartyAdminController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(SamlRelyingPartyConfigPublisher.class);
        metadataParser = mock(SamlSpMetadataParser.class);
        controller = new SamlRelyingPartyAdminController(publisher, metadataParser);
    }

    @SuppressWarnings("unchecked")
    private static String message(final ResponseEntity<?> response) {
        return ((Map<String, String>) response.getBody()).get("message");
    }

    @Test
    void importMetadata_withBlankXml_returns400_andNeverCallsTheParser() {
        final ResponseEntity<?> response = controller.importMetadata("master", new ImportMetadataRequest(""));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(message(response)).isEqualTo("Paste the SP's metadata XML first.");
        verify(metadataParser, never()).parse(anyString());
    }

    @Test
    void importMetadataUrl_withNonHttpScheme_returns400_mentioningHttp() {
        final ResponseEntity<?> response = controller.importMetadataUrl("master", new ImportMetadataUrlRequest("ftp://x"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(message(response)).contains("http://");
        verify(metadataParser, never()).parse(anyString());
    }

    @Test
    void importMetadataUrl_withBlankUrl_returns400() {
        final ResponseEntity<?> response = controller.importMetadataUrl("master", new ImportMetadataUrlRequest(""));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(metadataParser, never()).parse(anyString());
    }

    @Test
    void importMetadata_withParseableSp_returns200_andPrefilledRequest() {
        final ParsedSp parsed = new ParsedSp("https://sp.example/entity", "https://sp.example/acs",
                List.of(), "https://sp.example/slo", "CERT", null, false);
        when(metadataParser.parse(anyString())).thenReturn(parsed);

        final ResponseEntity<?> response = controller.importMetadata("master",
                new ImportMetadataRequest("<EntityDescriptor/>"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isInstanceOf(SamlRelyingPartyRequest.class);
        final SamlRelyingPartyRequest body = (SamlRelyingPartyRequest) response.getBody();
        assertThat(body.entityId()).isEqualTo("https://sp.example/entity");
        assertThat(body.assertionConsumerServiceUrl()).isEqualTo("https://sp.example/acs");
    }

    @Test
    void importMetadata_whenParserThrows_returns400_withFriendlyMessage() {
        when(metadataParser.parse(anyString()))
                .thenThrow(new IllegalStateException("Invalid SP metadata: unmarshaller is null"));

        final ResponseEntity<?> response = controller.importMetadata("master",
                new ImportMetadataRequest("<not-saml/>"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(message(response)).contains("Could not parse SAML metadata");
    }
}
