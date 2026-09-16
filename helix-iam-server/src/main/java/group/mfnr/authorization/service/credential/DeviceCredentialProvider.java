package group.mfnr.authorization.service.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.service.device.DeviceCredentialService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Helix IAM E4.1: the VeridPay-style device factor as an auto-discovered {@link CredentialProvider}
 * (type "device"). The login "input" is a JSON blob the publisher packs from the device assertion —
 * {@code deviceId} plus base64url {@code challenge} and {@code signature} — routed to
 * {@link DeviceCredentialService#verifyAssertion}.
 */
@Component
public class DeviceCredentialProvider implements CredentialProvider {

    private static final Logger LOG = LogManager.getLogger(DeviceCredentialProvider.class);

    private final DeviceCredentialService deviceService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public DeviceCredentialProvider(final DeviceCredentialService deviceService) {
        this.deviceService = deviceService;
    }

    @Override
    public String type() {
        return "device";
    }

    @Override
    public boolean verify(final String userId, final String input) {
        try {
            final JsonNode node = objectMapper.readTree(input);
            return deviceService.verifyAssertion(
                    userId,
                    node.path("deviceId").asText(),
                    urlDecode(node, "challenge"),
                    urlDecode(node, "signature"));
        } catch (final Exception e) {
            LOG.warn("Malformed device assertion input for user {}: {}", userId, e.getMessage());
            return false;
        }
    }

    private static byte[] urlDecode(final JsonNode node, final String field) {
        final String value = node.path(field).asText("");
        return value.isEmpty() ? new byte[0] : Base64.getUrlDecoder().decode(value);
    }
}
