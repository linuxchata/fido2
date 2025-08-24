// This code is intentionally duplicated from site.js.
// site.js is referenced in documentation, so it must remain simple and minimal.
// Any shared logic should be carefully mirrored here to avoid complexity in site.js.

$(function () {
    $("#registration-dc").on("click", function (event) {
        const usernameInput = $("#username-registration");
        const displayNameInput = $("#display-name-registration");
        const errorMessageSpan = $("#error-message-registration");

        const username = usernameInput.val();
        const displayName = displayNameInput.val();

        if (!isValidInput(username)) {
            errorMessageSpan.text("Please input a username");
            return;
        }

        if (!isValidInput(displayName)) {
            errorMessageSpan.text("Please input a display name");
            return;
        }

        usernameInput.prop("readonly", true);
        displayNameInput.prop("readonly", true);
        errorMessageSpan.text("");

        const button = event.target.closest('button');
        const previousInnerHtml = button.innerHTML;
        disableButton(button);

        registrationOfDiscoverableCredential(username, displayName)
            .finally(() => {
                usernameInput.prop("readonly", false);
                displayNameInput.prop("readonly", false);
                enableButton(button, previousInnerHtml);
            });
    });

    $("#authentication-dc").on("click", function (event) {
        const button = event.target.closest('button');
        const previousInnerHtml = button.innerHTML;
        disableButton(button);

        authenticationWithDiscoverableCredential()
            .finally(() => {
                enableButton(button, previousInnerHtml);
            });
    });
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
