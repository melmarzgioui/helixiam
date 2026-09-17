/*
 * Security review M3 (CSP): extracted from the inline <script> in flow/webauthn-form.html so the page runs
 * under `script-src 'self'` with NO 'unsafe-inline'. The per-request challenge + rpId are read from data-*
 * attributes on the form. Behaviour (including the auto-prompt on load) is identical to the inline version.
 */
(function () {
    'use strict';

    const form = document.getElementById('webauthnForm');
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

    async function startPasskey() {
        try {
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: b64urlToBytes(challengeB64),
                    rpId: rpId,
                    userVerification: 'preferred',
                    timeout: 60000
                }
            });
            const r = assertion.response;
            document.getElementById('credentialId').value = bytesToB64url(assertion.rawId);
            document.getElementById('authenticatorData').value = bytesToB64url(r.authenticatorData);
            document.getElementById('clientDataJSON').value = bytesToB64url(r.clientDataJSON);
            document.getElementById('signature').value = bytesToB64url(r.signature);
            document.getElementById('userHandle').value = r.userHandle ? bytesToB64url(r.userHandle) : '';
            form.submit();
        } catch (e) {
            console.error('Passkey failed', e);
        }
    }

    const webauthnBtn = document.getElementById('webauthnBtn');
    if (webauthnBtn) {
        webauthnBtn.addEventListener('click', startPasskey);
    }
    // Auto-prompt on load for a smoother UX.
    window.addEventListener('load', startPasskey);
})();
