/*
 * Task 18: the EUDI wallet page's status polling (flow/wallet.html). A static file: the page runs under
 * `script-src 'self'` without 'unsafe-inline'. Every ~2 s it asks /realms/{realm}/broker/{alias}/wallet/status?tx=…
 * (same origin, the session cookie binds it to this browser) and stops for good at the transaction's expiry.
 *   PENDING       - keep waiting
 *   WALLET_OPENED - the wallet fetched the request: "confirm in your wallet app"; the spent QR code is put away
 *   COMPLETED - follow `next` (the broker callback with this browser's response code) when present; a same-device
 *               login was already sent back by the wallet, so the page only says so
 *   FAILED    - say so, in the words of its plain-language `reason` (declined, not_accepted, expired, technical),
 *               and show the retry
 *   404       - expired or unknown: say so and show the retry
 * The status line is a polite live region while waiting (with a CSS spinner that honours prefers-reduced-motion); a
 * failure turns it into the house error alert (.hx-alert.hx-alert-error, role="alert") and moves focus to the retry.
 * The texts come from its data-msg-* attributes (localised by the server).
 */
(function () {
    'use strict';

    var INTERVAL_MS = 2000;
    var root = document.getElementById('wallet');
    var status = document.getElementById('walletStatus');
    if (!root || !status || !root.dataset.statusUrl) {
        return;
    }
    var statusUrl = root.dataset.statusUrl;
    var expiresAt = Number(root.dataset.expiresAt) || 0;
    var retry = document.getElementById('walletRetry');
    var active = document.getElementById('walletActive');
    var dcApi = document.getElementById('walletDcApi');
    var dcApiButton = document.getElementById('walletDcApiButton');
    var stopped = false;

    // The Digital Credentials API section (wallet-dcapi.js) is spent too once another path took the login, unless it
    // is the path in progress (its button is disabled while it runs).
    function hideDcApi() {
        if (dcApi && !(dcApiButton && dcApiButton.disabled)) {
            dcApi.hidden = true;
        }
    }

    var opened = false;

    function say(message) {
        if (message) {
            status.textContent = message;
        }
    }

    function stop(message, failure) {
        stopped = true;
        status.classList.remove('is-waiting');
        if (failure) {
            // the codebase's error treatment (qr-login / push pages), announced assertively
            status.className = 'hx-alert hx-alert-error';
            status.removeAttribute('aria-live');
            status.setAttribute('role', 'alert');
        }
        say(message);
        if (failure) {
            if (active) {
                active.hidden = true; // the QR code and the link are spent
            }
            hideDcApi();
            if (retry) {
                retry.hidden = false;
                retry.focus();
            }
        }
    }

    // The failure's plain-language class picks its message; anything unknown reads as a technical failure.
    var FAILURE_MESSAGES = {
        declined: 'msgFailedDeclined',
        not_accepted: 'msgFailedNotAccepted',
        expired: 'msgFailedExpired'
    };

    function failureMessage(reason) {
        var key = Object.prototype.hasOwnProperty.call(FAILURE_MESSAGES, reason) ? FAILURE_MESSAGES[reason] : null;
        return (key && status.dataset[key]) || status.dataset.msgFailed;
    }

    function walletOpened() {
        if (opened) {
            return;
        }
        opened = true;
        if (active) {
            active.hidden = true; // the wallet has the request: the QR code and the link are spent
        }
        hideDcApi();
        say(status.dataset.msgOpened);
    }

    // Only a same-origin path ("/realms/…"), never "//host" or a scheme: the server builds it, this is a seatbelt.
    function isLocalPath(next) {
        return typeof next === 'string' && next.charAt(0) === '/' && next.charAt(1) !== '/' && next.charAt(1) !== '\\';
    }

    function expired() {
        return expiresAt > 0 && Date.now() >= expiresAt;
    }

    function schedule() {
        if (stopped) {
            return;
        }
        if (expired()) {
            stop(status.dataset.msgExpired, true);
            return;
        }
        var wait = expiresAt > 0 ? Math.max(0, Math.min(INTERVAL_MS, expiresAt - Date.now())) : INTERVAL_MS;
        window.setTimeout(poll, wait);
    }

    function poll() {
        if (stopped) {
            return;
        }
        if (expired()) {
            stop(status.dataset.msgExpired, true);
            return;
        }
        fetch(statusUrl, { headers: { 'Accept': 'application/json' }, credentials: 'same-origin', cache: 'no-store' })
            .then(function (response) {
                if (response.status === 404) {
                    stop(status.dataset.msgExpired, true);
                    return null;
                }
                return response.ok ? response.json() : null;
            })
            .then(function (data) {
                if (stopped || !data) {
                    schedule();
                    return;
                }
                if (data.status === 'COMPLETED') {
                    if (isLocalPath(data.next)) {
                        stop(status.dataset.msgCompleted, false);
                        window.location.assign(data.next);
                    } else {
                        stop(status.dataset.msgCompletedElsewhere, false);
                    }
                    return;
                }
                if (data.status === 'FAILED') {
                    stop(failureMessage(data.reason), true);
                    return;
                }
                if (data.status === 'WALLET_OPENED') {
                    walletOpened();
                }
                schedule();
            })
            .catch(function () {
                schedule(); // a network blip: keep polling until the expiry
            });
    }

    schedule();
})();
