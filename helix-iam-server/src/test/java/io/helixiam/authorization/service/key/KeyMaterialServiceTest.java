package io.helixiam.authorization.service.key;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.realm.RealmKey;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM multi-tenant (MT-3): the JWKS/signing material is selected per realm. A non-admin
 * realm gets its OWN generated key ({@code getOrCreateActive}) and never touches the {@code /jks}
 * seed (which is reserved for the admin realm's token continuity).
 */
class KeyMaterialServiceTest {

    private static RealmKey realmKeyFrom(final String realm, final KeyPair pair) {
        return new RealmKey("kid-" + realm, realm, "RSA",
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
    }

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @Test
    void activeKeyPair_forNonAdminRealm_generatesItsOwnKey_withoutTouchingJks() throws Exception {
        final RealmKeyService realmKeyService = mock(RealmKeyService.class);
        final KeyPair govPair = rsa();
        when(realmKeyService.getOrCreateActive("gov")).thenReturn(realmKeyFrom("gov", govPair));

        final KeyMaterialService service = new KeyMaterialService(realmKeyService);
        final KeyPair result = service.activeKeyPair("gov");

        assertNotNull(result);
        assertEquals(((RSAPublicKey) govPair.getPublic()).getModulus(),
                ((RSAPublicKey) result.getPublic()).getModulus());
        assertEquals(((RSAPrivateKey) govPair.getPrivate()).getModulus(),
                ((RSAPrivateKey) result.getPrivate()).getModulus());
        // A non-admin realm must NOT seed from the shared /jks keypair.
        verify(realmKeyService, never()).getOrImportActive(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void activeKeyPair_forSigningRealm_selfGeneratesWhenNoJksMounted() throws Exception {
        // Standalone deployment (the default): no /jks keypair on filesystem or classpath, so the
        // signing/admin realm must self-generate its own key rather than fail on a missing mount.
        final RealmKeyService realmKeyService = mock(RealmKeyService.class);
        final KeyPair masterPair = rsa();
        when(realmKeyService.getOrCreateActive(KeyMaterialService.SIGNING_REALM_ID))
                .thenReturn(realmKeyFrom(KeyMaterialService.SIGNING_REALM_ID, masterPair));

        final KeyMaterialService service = new KeyMaterialService(realmKeyService);
        final KeyPair result = service.activeKeyPair(KeyMaterialService.SIGNING_REALM_ID);

        assertNotNull(result);
        assertEquals(((RSAPublicKey) masterPair.getPublic()).getModulus(),
                ((RSAPublicKey) result.getPublic()).getModulus());
        // No /jks present → self-generate, never import.
        verify(realmKeyService).getOrCreateActive(KeyMaterialService.SIGNING_REALM_ID);
        verify(realmKeyService, never()).getOrImportActive(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void rotatedPublicKeys_forRealm_returnsThatRealmsRotatedKeys() throws Exception {
        final RealmKeyService realmKeyService = mock(RealmKeyService.class);
        final RealmKey rotated = realmKeyFrom("gov", rsa());
        rotated.setStatus(RealmKey.Status.ROTATED);
        when(realmKeyService.verificationKeys("gov")).thenReturn(java.util.List.of(rotated));

        final KeyMaterialService service = new KeyMaterialService(realmKeyService);

        assertEquals(1, service.rotatedPublicKeys("gov").size());
    }

    @Test
    void adminRealmConstant_isMaster() {
        assertEquals(RealmConfig.ADMIN_REALM_ID, KeyMaterialService.SIGNING_REALM_ID);
    }
}
