/*
 * Security review M3 (CSP): extracted from the inline <script> in flow/qr-login-form.html so the page runs
 * under `script-src 'self'` with NO 'unsafe-inline'. The per-request session id + rotating token are read
 * from data-* attributes on the form. Behaviour (deep-link render + short-poll) is unchanged.
 */
(function () {
    'use strict';

    const form = document.getElementById('qrForm');
    if (!form) {
        return;
    }
    const sessionId = form.dataset.sessionId || '';
    let token = form.dataset.token || '';

    // Render the cross-device deep link the phone scans. (A QR image lib renders this in the app/UX;
    // shown as text here so the flow is functional without bundling a QR renderer.)
    function renderLink() {
        document.getElementById('qrLink').textContent = 'helix://qr-login/' + sessionId + '?t=' + token;
    }

    // Short-poll the shared store. Deliberately NOT SSE: polling is stateless and any publisher
    // instance can answer, so it scales horizontally without held connections or cross-node push.
    async function poll() {
        try {
            const res = await fetch('/qr/' + encodeURIComponent(sessionId), { headers: { 'Accept': 'application/json' } });
            const data = await res.json();
            if (data.token) { token = data.token; renderLink(); }
            if (data.status === 'CONFIRMED') {
                document.getElementById('qrStatus').textContent = 'Approved — signing you in…';
                form.submit(); // run the authenticator action (consume + login)
                return;
            }
            if (data.status === 'EXPIRED') {
                document.getElementById('qrStatus').textContent = 'This code expired. Refresh to try again.';
                return;
            }
        } catch (e) { /* transient — keep polling */ }
        setTimeout(poll, 2500);
    }

    renderLink();
    setTimeout(poll, 2500);
})();
