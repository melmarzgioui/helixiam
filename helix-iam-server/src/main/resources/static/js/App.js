function backButton() {
    const cancel = document.getElementsByClassName("cancel");
    for(let x = 0; x < cancel.length; x++) {
        if (cancel[x].dataset.href) {
            cancel[x].onclick = function() {
                // The realm's own sign-in page (the template renders it realm-prefixed); /login alone is not served.
                document.location.href = this.dataset.href
            }
        }
    }


    const continueLogin = document.getElementsByClassName("continueLogin");
    for(let x = 0; x < continueLogin.length; x++) {
        // Links (<a href>) navigate by themselves; only buttons carry their target in data-href.
        if (continueLogin[x].dataset.href) {
            continueLogin[x].onclick = function() {
                document.location.href = this.dataset.href
            }
        }
    }

    const showCode = document.getElementById("showCode");
    if(showCode !== undefined && showCode != null) {
        showCode.onclick = function() {
            document.getElementById('setupKey').className = "";
        }
    }
}

if (document.readyState !== 'loading') {
    backButton()
} else {
    document.addEventListener('DOMContentLoaded', function () {
        backButton()
    });
}