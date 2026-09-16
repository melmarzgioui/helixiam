package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyRef;
import io.helixiam.authorization.amqp.saml.SamlSpOptions;
import io.helixiam.authorization.idp.saml.SamlSpMetadataParser;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * Helix IAM: admin REST API for per-realm SAML2 relying parties (SPs) — the backend behind the
 * console's "SAML clients" screen. The realm is always taken from the path so an SP can only be
 * written into its own realm; the store is owned by the identity domain (subscriber) and reached over
 * AMQP. The SAML IdP reads the same store at request time, so a change here takes effect with no
 * restart. Mirrors {@code ClientAdminController} / {@code IdentityProviderAdminController}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/saml-clients")
public class SamlRelyingPartyAdminController {

    private final SamlRelyingPartyConfigPublisher publisher;
    private final SamlSpMetadataParser metadataParser;

    public SamlRelyingPartyAdminController(final SamlRelyingPartyConfigPublisher publisher,
                                           final SamlSpMetadataParser metadataParser) {
        this.publisher = publisher;
        this.metadataParser = metadataParser;
    }

    /**
     * WSO2-class onboarding: parse an uploaded SP metadata XML into a pre-filled relying-party request.
     * Returns 400 with a {@code {"message":...}} body (NOT a thrown exception — that would route through the
     * security-guarded /error dispatch and redirect) so the console can show the reason inline.
     */
    @PostMapping("/import")
    public ResponseEntity<?> importMetadata(@PathVariable final String realmId,
                                            @RequestBody final ImportMetadataRequest body) {
        final String xml = body.metadataXml();
        if (xml == null || xml.isBlank()) {
            return badRequest("Paste the SP's metadata XML first.");
        }
        return parseToResponse(xml);
    }

    /**
     * WSO2/URL onboarding: fetch an SP's metadata from its published endpoint and parse it
     * into a pre-filled request. Fetched server-side so it works cross-origin and behind the dashboard proxy.
     */
    @PostMapping("/import-url")
    public ResponseEntity<?> importMetadataUrl(@PathVariable final String realmId,
                                               @RequestBody final ImportMetadataUrlRequest body) {
        final String url = body.url() == null ? "" : body.url().trim();
        final URI uri;
        try {
            uri = URI.create(url);
        } catch (final RuntimeException e) {
            return badRequest("That is not a valid URL.");
        }
        final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return badRequest("Metadata URL must start with http:// or https://");
        }
        final String xml;
        try {
            final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8))
                    .followRedirects(HttpClient.Redirect.NORMAL).build();
            final HttpResponse<String> res = client.send(
                    HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).header("Accept", "application/samlmetadata+xml, application/xml, text/xml").GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() / 100 != 2) {
                return badRequest("Metadata endpoint returned HTTP " + res.statusCode() + ".");
            }
            xml = res.body();
        } catch (final Exception e) {
            final String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return badRequest("Could not fetch metadata from that URL: " + why);
        }
        if (xml == null || xml.isBlank()) {
            return badRequest("Metadata endpoint returned an empty document.");
        }
        return parseToResponse(xml);
    }

    /** Parse SP metadata XML into a pre-filled request (200), or a 400 {@code {"message":...}} on failure. */
    private ResponseEntity<?> parseToResponse(final String xml) {
        final SamlSpMetadataParser.ParsedSp sp;
        try {
            sp = metadataParser.parse(xml);
        } catch (final RuntimeException e) {
            // OpenSAML's low-level message ("unmarshaller is null", etc.) is meaningless to an admin.
            final String msg = e.getMessage();
            final boolean noSpDescriptor = msg != null && msg.contains("SPSSODescriptor");
            return badRequest(noSpDescriptor
                    ? "Valid XML, but it has no SPSSODescriptor — that is IdP or unrelated metadata, not a service provider's."
                    : "Could not parse SAML metadata — expected a service provider <EntityDescriptor> document.");
        }
        if (sp.entityId() == null || sp.entityId().isBlank()) {
            return badRequest("No SP entityID found in the metadata.");
        }
        // SP metadata's WantAssertionsSigned maps to our signAssertion (the IdP signs the assertion).
        final SamlSpOptions options = new SamlSpOptions(sp.wantAssertionsSigned() ? true : null, null, null,
                null, null, null, null, null, sp.nameIdFormat(), null,
                sp.additionalAcsUrls(), null, null, null, null, null);
        return ResponseEntity.ok(new SamlRelyingPartyRequest(sp.entityId(), sp.assertionConsumerServiceUrl(), null,
                sp.singleLogoutServiceUrl(), sp.signingCertificate(), true, null, options));
    }

    private static ResponseEntity<?> badRequest(final String message) {
        return ResponseEntity.badRequest().body(java.util.Map.of("message", message == null ? "Invalid metadata." : message));
    }

    /** Body for {@code POST /import} — the raw SP {@code <EntityDescriptor>} XML. */
    public record ImportMetadataRequest(String metadataXml) {
    }

    /** Body for {@code POST /import-url} — the SP's published metadata endpoint. */
    public record ImportMetadataUrlRequest(String url) {
    }

    @GetMapping
    public List<SamlRelyingPartyConfig> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{entityId}")
    public ResponseEntity<SamlRelyingPartyConfig> get(@PathVariable final String realmId,
                                                      @PathVariable final String entityId) {
        final SamlRelyingPartyConfig config = publisher.get(new SamlRelyingPartyRef(realmId, entityId));
        return config == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(config);
    }

    @PostMapping
    public ResponseEntity<SamlRelyingPartyConfig> create(@PathVariable final String realmId,
                                                         @Valid @RequestBody final SamlRelyingPartyRequest request) {
        final SamlRelyingPartyConfig saved = publisher.save(toConfig(realmId, request.entityId(), request));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{entityId}")
    public ResponseEntity<SamlRelyingPartyConfig> update(@PathVariable final String realmId,
                                                         @PathVariable final String entityId,
                                                         @Valid @RequestBody final SamlRelyingPartyRequest request) {
        final SamlRelyingPartyConfig saved = publisher.save(toConfig(realmId, entityId, request));
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{entityId}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String entityId) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new SamlRelyingPartyRef(realmId, entityId)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static SamlRelyingPartyConfig toConfig(final String realmId, final String entityId,
                                                   final SamlRelyingPartyRequest request) {
        return new SamlRelyingPartyConfig(realmId, entityId, request.assertionConsumerServiceUrl(),
                request.defaultAuthnContextClassRef(), request.singleLogoutServiceUrl(),
                request.signingCertificate(), request.enabled() == null || request.enabled(),
                request.applicationId(), request.options());
    }
}
