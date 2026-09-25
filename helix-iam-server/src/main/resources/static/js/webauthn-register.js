/*
 * Security review M3 (CSP): extracted from the inline <script> in mfa/webauthn-register.html so the page
 * runs under `script-src 'self'` with NO 'unsafe-inline'. The per-request WebAuthn ceremony values that
 * used to be templated into JS (Thymeleaf th:inline="javascript") are now read from data-* attributes on
 * the registration form. Behaviour is byte-for-byte identical to the previous inline version.
 */
(function () {
    'use strict';

    const form = document.getElementById('regForm');
    if (!form) {
        return;
    }
    const challengeB64 = form.dataset.challenge || '';
    const rpId = form.dataset.rpId || 'localhost';
    const userId = form.dataset.userId || '';
    const username = form.dataset.username || '';

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

    function strToBytes(s) {
        return new TextEncoder().encode(s).buffer;
    }

    async function createPasskey() {
        try {
            const cred = await navigator.credentials.create({
                publicKey: {
                    challenge: b64urlToBytes(challengeB64),
                    rp: { id: rpId, name: 'HelixIAM' },
                    user: { id: strToBytes(userId), name: username, displayName: username },
                    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
                    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
                    timeout: 60000,
                    attestation: 'none'
                }
            });
            document.getElementById('attestationObject').value = bytesToB64url(cred.response.attestationObject);
            document.getElementById('clientDataJSON').value = bytesToB64url(cred.response.clientDataJSON);
            form.submit();
        } catch (e) {
            console.error('Passkey registration failed', e);
        }
    }

    const regBtn = document.getElementById('regBtn');
    if (regBtn) {
        regBtn.addEventListener('click', createPasskey);
    }
})();
