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
    $(".btn-primary").on("click", function (event) {
        let actionType = $(this).data("action");
        let usernameInput = $("#username");
        let displayNameInput = $("#displayName");
        let messageSpan = $("#message");
        let username = usernameInput.val();
        let displayName = displayNameInput.val();

        if (isRegister(actionType) && !isValidInput(username)) {
            messageSpan.text("Please input a username");
            return;
        }

        usernameInput.prop("readonly", true);
        displayNameInput.prop("readonly", true);
        messageSpan.text("");

        let button = event.target;
        let previousText = button.innerHTML;
        disableButton(button);

        (isRegister(actionType) ?
            requestCreateCredentialOptions(username, displayName) :
            requestVerifyCredentialOptions(username))
            .finally(() => {
                usernameInput.prop("readonly", false);
                displayNameInput.prop("readonly", false);
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