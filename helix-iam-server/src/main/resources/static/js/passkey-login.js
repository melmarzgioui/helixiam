/*
 * Security review M3 (CSP): extracted from the inline <script> in flow/passkey-login-form.html so the page
 * runs under `script-src 'self'` with NO 'unsafe-inline'. The per-request challenge + rpId are read from
 * data-* attributes on the form. Behaviour (conditional-UI autofill + modal fallback) is unchanged.
 */
(function () {
    'use strict';

    const form = document.getElementById('passkeyForm');
    if (!form) {
        return;
    }
    const challengeB64 = form.dataset.challenge || '';
    const rpId = form.dataset.rpId || 'localhost';

    function b64urlToBytes(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        const bin = atob(s);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
    }

    function bytesToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function submitAssertion(assertion) {
        const r = assertion.response;
        document.getElementById('credentialId').value = bytesToB64url(assertion.rawId);
        document.getElementById('authenticatorData').value = bytesToB64url(r.authenticatorData);
        document.getElementById('clientDataJSON').value = bytesToB64url(r.clientDataJSON);
        document.getElementById('signature').value = bytesToB64url(r.signature);
        document.getElementById('userHandle').value = r.userHandle ? bytesToB64url(r.userHandle) : '';
        form.submit();
    }

    // Usernameless / resident-key: NO allowCredentials, so the authenticator offers discoverable passkeys
    // and the userHandle in the response identifies the signer (resolved server-side).
    function publicKeyOptions() {
        return {
            challenge: b64urlToBytes(challengeB64),
            rpId: rpId,
            userVerification: 'required',
            timeout: 60000
        };
    }

    // Conditional UI: prompt inline in the autofill dropdown if the browser supports it.
    async function startConditional() {
        try {
            if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;
            if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
            const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions(), mediation: 'conditional' });
            if (assertion) submitAssertion(assertion);
        } catch (e) {
            console.debug('Conditional passkey UI unavailable', e);
        }
    }

    // Explicit modal prompt on button click (fallback / user-initiated).
    async function startModal() {
        try {
            const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions() });
            if (assertion) submitAssertion(assertion);
        } catch (e) {
            console.error('Passkey login failed', e);
        }
    }

    const passkeyBtn = document.getElementById('passkeyBtn');
    if (passkeyBtn) {
        passkeyBtn.addEventListener('click', startModal);
    }
    window.addEventListener('load', startConditional);
})();
