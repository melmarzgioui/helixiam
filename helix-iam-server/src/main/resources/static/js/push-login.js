/*
 * Security review M3 (CSP): extracted from the inline <script> in flow/push-form.html so the page runs
 * under `script-src 'self'` with NO 'unsafe-inline'. The per-request push id is read from a data-* attribute
 * on the form. Behaviour (short-poll of the approval store) is unchanged.
 */
(function () {
    'use strict';

    const form = document.getElementById('pushForm');
    if (!form) {
        return;
    }
    const pushId = form.dataset.pushId || '';

    // Short-poll the shared store (NOT SSE) — stateless and node-agnostic, so it scales horizontally.
    async function poll() {
        try {
            const res = await fetch('/push/' + encodeURIComponent(pushId), { headers: { 'Accept': 'application/json' } });
            const data = await res.json();
            if (data.status === 'APPROVED') {
                document.getElementById('pushStatus').textContent = 'Approved — signing you in…';
                form.submit(); // run the authenticator action (consume + login)
                return;
            }
            if (data.status === 'DENIED' || data.status === 'EXPIRED' || data.status === 'UNKNOWN') {
                document.getElementById('pushStatus').textContent = 'Request ' + data.status.toLowerCase() + '. Refresh to try again.';
                return;
            }
        } catch (e) { /* transient — keep polling */ }
        setTimeout(poll, 2500);
    }

    setTimeout(poll, 2500);
})();
