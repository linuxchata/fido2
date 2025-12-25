document.addEventListener("DOMContentLoaded", function () {
    const registrationButton = document.getElementById("registration");
    if (registrationButton) {
        registrationButton.addEventListener("click", function (event) {
            const usernameInput = document.getElementById("username-registration");
            const displayNameInput = document.getElementById("display-name-registration");
            const errorMessageSpan = document.getElementById("error-message-registration");

            const username = usernameInput.value;
            const displayName = displayNameInput.value;

            if (!isValidInput(username)) {
                errorMessageSpan.textContent = "Please input a username";
                return;
            }

            if (!isValidInput(displayName)) {
                errorMessageSpan.textContent = "Please input a display name";
                return;
            }

            usernameInput.readOnly = true;
            displayNameInput.readOnly = true;
            errorMessageSpan.textContent = "";

            const button = event.target.closest('button');
            const previousInnerHtml = button.innerHTML;
            disableButton(button);

            registration(username, displayName)
                .finally(() => {
                    usernameInput.readOnly = false;
                    displayNameInput.readOnly = false;
                    enableButton(button, previousInnerHtml);
                });
        });
    }

    const authenticationButton = document.getElementById("authentication");
    if (authenticationButton) {
        authenticationButton.addEventListener("click", function (event) {
            const button = event.target.closest('button');
            const previousInnerHtml = button.innerHTML;
            disableButton(button);

            authentication()
                .finally(() => {
                    enableButton(button, previousInnerHtml);
                });
        });
    }
});

function isValidInput(value) {
    return value && value.trim().length > 0;
}

function disableButton(button) {
    button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Processing...';
    button.disabled = true;
}

function enableButton(button, previousInnerHtml) {
    button.innerHTML = previousInnerHtml;
    button.disabled = false;
}
