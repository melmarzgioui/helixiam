function backButton() {
    const cancel = document.getElementsByClassName("cancel");
    for(let x = 0; x < cancel.length; x++) {
        cancel[x].onclick = function() {
            // The realm's own sign-in page (the template renders it realm-prefixed); /login alone is not served.
            document.location.href = this.dataset.href || "login"
        }
    }


    const continueLogin = document.getElementsByClassName("continueLogin");
    for(let x = 0; x < continueLogin.length; x++) {
        continueLogin[x].onclick = function() {
            document.location.href = this.dataset.href || "login"
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