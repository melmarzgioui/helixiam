import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIdpMetadata } from '../lib/saml.js';

const META = `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://idp/realms/master">
<md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIDcert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://idp/realms/master/saml/idp/slo"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://idp/realms/master/saml/idp/sso"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://idp/realms/master/saml/idp/sso"/>
</md:IDPSSODescriptor></md:EntityDescriptor>`;

test('parseIdpMetadata extracts entityID, cert and the Redirect-binding SSO/SLO URLs', () => {
  const idp = parseIdpMetadata(META);
  assert.equal(idp.entityId, 'http://idp/realms/master');
  assert.equal(idp.cert, 'MIIDcert==');
  // must pick the HTTP-Redirect SSO location, not the POST one (both share the same URL here)
  assert.equal(idp.ssoUrl, 'http://idp/realms/master/saml/idp/sso');
  assert.equal(idp.sloUrl, 'http://idp/realms/master/saml/idp/slo');
});

test('parseIdpMetadata throws when the certificate is absent', () => {
  assert.throws(() => parseIdpMetadata('<md:EntityDescriptor entityID="x"></md:EntityDescriptor>'));
});
