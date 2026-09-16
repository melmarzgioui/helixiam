package io.helixiam.authorization.federation.eid;

import java.util.Map;

/**
 * Helix IAM E6: a validated (signature-verified, decrypted, LoA-checked) eID assertion.
 *
 * @param subjectId            the decrypted subject identifier (BSN / KvK number / eIDAS PersonIdentifier).
 *                             In a representation flow this is the <b>represented</b> party (the person/
 *                             company acted for).
 * @param subjectType          the identifier type carried as the EncryptedID NameQualifier
 *                             (e.g. {@code urn:nl-eid-gdi:1.0:id:legacy-BSN},
 *                             {@code urn:etoegang:1.12:EntityConcernedID:BSN}); null for plain NameIDs
 * @param authnContextClassRef the asserted level of assurance
 * @param attributes           the remaining (decrypted) attributes
 * @param representation       present for DigiD Machtigen / eHerkenning representation flows: the acting
 *                             subject (the representative who authenticated) + the mandated service; null
 *                             for a plain (non-representation) login
 */
public record EidAssertion(String subjectId, String subjectType, String authnContextClassRef,
                           Map<String, String> attributes, Representation representation) {

    /**
     * Representation / mandate context: the {@code actingSubjectId} is the party that authenticated and
     * is acting on behalf of the {@link EidAssertion#subjectId()} (represented party), for the mandated
     * {@code serviceId}.
     */
    public record Representation(String actingSubjectId, String serviceId) {
    }

    /** A plain (non-representation) assertion. */
    public EidAssertion(final String subjectId, final String subjectType, final String authnContextClassRef,
                        final Map<String, String> attributes) {
        this(subjectId, subjectType, authnContextClassRef, attributes, null);
    }
}
