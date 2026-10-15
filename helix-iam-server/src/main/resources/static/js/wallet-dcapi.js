/*
 * OpenID4VP over the W3C Digital Credentials API (OpenID4VP 1.0 Appendix A, HAIP 1.0 §5.2) on the EUDI wallet page
 * (flow/wallet.html). A static file: the page runs under `script-src 'self'` without 'unsafe-inline'.
 *
 * Progressive enhancement: the #walletDcApi section stays hidden unless the browser has the API
 * (window.DigitalCredential and navigator.credentials.get) and, where it can say so, allows the provider's protocol
 * (DigitalCredential.userAgentAllowsProtocol). Without it the page is the QR code and "Open wallet app", unchanged.
 *
 * "Continue with your wallet":
 *   1. POST data-request-url (same origin, session cookie, CSRF header) -> {protocol, data}
 *   2. navigator.credentials.get({mediation: 'required', digital: {requests: [{protocol, data}]}})
 *   3. POST data-response-url with {protocol, data} of the returned DigitalCredential
 *   4. COMPLETED -> follow `next` (a same-origin path: the broker callback with this browser's response code); a
 *      COMPLETED without `next` means the status poll got the one code first, so wallet-poll.js navigates;
 *      FAILED -> show the plain-language reason; the server decides, this page never trusts the wallet's answer.
 * A cancelled browser sheet (AbortError / NotAllowedError) changes nothing on the server: the QR code and the link
 * still work, and the button can be pressed again.
 */
(function () {
    'use strict';

    var root = document.getElementById('walletDcApi');
    var button = document.getElementById('walletDcApiButton');
    var note = document.getElementById('walletDcApiNote');
    var status = document.getElementById('walletStatus');
    if (!root || !button || !root.dataset.requestUrl || !root.dataset.responseUrl) {
        return;
    }
    var protocol = root.dataset.protocol;

    function supported() {
        if (typeof window.DigitalCredential === 'undefined' || !navigator.credentials
                || typeof navigator.credentials.get !== 'function') {
            return false;
        }
        var allows = window.DigitalCredential.userAgentAllowsProtocol;
        if (typeof allows === 'function') {
            try {
                return allows.call(window.DigitalCredential, protocol) !== false;
            } catch (e) {
                return false;
            }
        }
        return true;
    }

    if (!supported()) {
        return; // the QR code and "Open wallet app" are the whole page
    }
    root.hidden = false;

    function say(message) {
        note.textContent = message || '';
    }

    // Only a same-origin path ("/realms/…"), never "//host" or a scheme: the server builds it, this is a seatbelt.
    function isLocalPath(next) {
        return typeof next === 'string' && next.charAt(0) === '/' && next.charAt(1) !== '/' && next.charAt(1) !== '\\';
    }

    function post(url, body) {
        var headers = { 'Accept': 'application/json' };
        if (body !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        if (root.dataset.csrfHeader && root.dataset.csrfToken) {
            headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
        }
        return fetch(url, {
            method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: headers,
            body: body === undefined ? undefined : JSON.stringify(body)
        });
    }

    function failed(reason) {
        // The page's own status line and retry (wallet-poll.js) show the outcome in the house style.
        var keys = { declined: 'msgFailedDeclined', not_accepted: 'msgFailedNotAccepted', expired: 'msgFailedExpired' };
        var key = Object.prototype.hasOwnProperty.call(keys, reason) ? keys[reason] : 'msgFailed';
        root.hidden = true;
        if (status) {
            status.className = 'hx-alert hx-alert-error';
            status.removeAttribute('aria-live');
            status.setAttribute('role', 'alert');
            status.textContent = status.dataset[key] || status.dataset.msgFailed || '';
        }
        var active = document.getElementById('walletActive');
        if (active) {
            active.hidden = true;
        }
        var retry = document.getElementById('walletRetry');
        if (retry) {
            retry.hidden = false;
            retry.focus();
        }
    }

    button.addEventListener('click', function () {
        button.disabled = true;
        say(root.dataset.msgWaiting);
        var request;
        post(root.dataset.requestUrl)
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('request');
                }
                return response.json();
            })
            .then(function (body) {
                request = body;
                return navigator.credentials.get({
                    mediation: 'required',
                    digital: { requests: [{ protocol: body.protocol, data: body.data }] }
                });
            })
            .then(function (credential) {
                if (!credential || !credential.data) {
                    throw new Error('empty');
                }
                say(root.dataset.msgChecking);
                var data = credential.data;
                if (typeof data === 'string') {
                    data = JSON.parse(data);
                }
                return post(root.dataset.responseUrl, {
                    protocol: credential.protocol || request.protocol,
                    data: data
                }).then(function (response) {
                    return response.json().catch(function () {
                        return {};
                    });
                });
            })
            .then(function (result) {
                if (result && result.status === 'COMPLETED') {
                    if (status) {
                        status.textContent = status.dataset.msgCompleted || '';
                    }
                    if (isLocalPath(result.next)) {
                        window.location.assign(result.next);
                    }
                    // COMPLETED without `next`: the status poll (wallet-poll.js) raced us and was issued this
                    // browser's one response code; it navigates. Stay in the waiting state, never show an error.
                    return;
                }
                failed(result && result.reason);
            })
            .catch(function (error) {
                button.disabled = false;
                var name = error && error.name;
                say(name === 'AbortError' || name === 'NotAllowedError' ? root.dataset.msgCancelled
                    : root.dataset.msgUnavailable);
            });
    });
})();
