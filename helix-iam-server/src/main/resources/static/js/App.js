function backButton() {
    const cancel = document.getElementsByClassName("cancel");
    for(let x = 0; x < cancel.length; x++) {
        cancel[x].onclick = function() {
            document.location.href = "/login"
        }
    }


    const continueLogin = document.getElementsByClassName("continueLogin");
    for(let x = 0; x < continueLogin.length; x++) {
        continueLogin[x].onclick = function() {
            document.location.href = "/login"
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