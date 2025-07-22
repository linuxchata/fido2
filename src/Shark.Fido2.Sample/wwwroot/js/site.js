toastr.options = {
    "positionClass": "toast-top-right",
    "timeOut": "5000",
    "closeButton": true,
    "showEasing": "swing",
    "hideEasing": "linear",
    "showMethod": "fadeIn",
    "hideMethod": "fadeOut"
};

$(function () {
    $("#register").on("click", function (event) {
        const usernameInput = $("#username-register");
        const displayNameInput = $("#display-name-register");
        const messageSpan = $("#message-register");
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

        requestCreateCredentialOptions(username, displayName)
            .finally(() => {
                usernameInput.prop("readonly", false);
                displayNameInput.prop("readonly", false);
                enableButton(button, previousText);
            });
    });

    $("#authenticate").on("click", function (event) {
        const usernameInput = $("#username-authenticate");
        const messageSpan = $("#message-authenticate");
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

        requestVerifyCredentialOptions(username)
            .finally(() => {
                usernameInput.prop("readonly", false);
                enableButton(button, previousText);
            });
    });
});

function isRegister(actionType) {
    return actionType === "register";
}

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