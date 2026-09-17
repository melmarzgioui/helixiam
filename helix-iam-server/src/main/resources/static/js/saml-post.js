/*
 * Security review M3 (CSP): replaces the inline `onload="document.forms[0].submit()"` handler in
 * flow/saml-post.html so the SAML HTTP-POST binding auto-submits under `script-src 'self'` with NO
 * 'unsafe-inline'. The <noscript> fallback button in the template still covers JS-disabled browsers.
 */
(function () {
    'use strict';

    function submitAuthnRequest() {
        if (document.forms.length > 0) {
            document.forms[0].submit();
        }
    }

    if (document.readyState !== 'loading') {
        submitAuthnRequest();
    } else {
        document.addEventListener('DOMContentLoaded', submitAuthnRequest);
    }
})();
