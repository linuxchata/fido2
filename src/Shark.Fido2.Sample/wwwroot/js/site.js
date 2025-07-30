$(function () {
    $("#registration").on("click", function (event) {
        const usernameInput = $("#username-registration");
        const displayNameInput = $("#display-name-registration");
        const messageSpan = $("#message-registration");

        const username = usernameInput.val();
        const displayName = displayNameInput.val();

        if (!isValidInput(username)) {
            messageSpan.text("Please input a username");
            return;
        }

        if (!isValidInput(displayName)) {
            messageSpan.text("Please input a display name");
            return;
        }

        usernameInput.prop("readonly", true);
        displayNameInput.prop("readonly", true);
        messageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        registration(username, displayName)
            .finally(() => {
                usernameInput.prop("readonly", false);
                displayNameInput.prop("readonly", false);
                enableButton(button, previousText);
            });
    });

    $("#authentication").on("click", function (event) {
        const usernameInput = $("#username-authentication");
        const messageSpan = $("#message-authentication");
        const username = usernameInput.val();

        if (!isValidInput(username)) {
            messageSpan.text("Please input a username");
            return;
        }

        usernameInput.prop("readonly", true);
        messageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        authentication(username)
            .finally(() => {
                usernameInput.prop("readonly", false);
                enableButton(button, previousText);
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

function enableButton(button, previousText) {
    button.innerHTML = previousText;
    button.disabled = false;
}
