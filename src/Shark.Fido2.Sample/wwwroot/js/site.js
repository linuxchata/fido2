$(function () {
    $("#registration").on("click", function (event) {
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

        registration(username, displayName)
            .finally(() => {
                usernameInput.prop("readonly", false);
                displayNameInput.prop("readonly", false);
                enableButton(button, previousInnerHtml);
            });
    });

    $("#authentication").on("click", function (event) {
        const usernameInput = $("#username-authentication");
        const errorMessageSpan = $("#error-message-authentication");
        const username = usernameInput.val();

        if (!isValidInput(username)) {
            errorMessageSpan.text("Please input a username");
            return;
        }

        usernameInput.prop("readonly", true);
        errorMessageSpan.text("");

        const button = event.target.closest('button');
        const previousInnerHtml = button.innerHTML;
        disableButton(button);

        authentication(username)
            .finally(() => {
                usernameInput.prop("readonly", false);
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
