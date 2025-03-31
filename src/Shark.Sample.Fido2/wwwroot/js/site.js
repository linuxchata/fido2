toastr.options = {
    "positionClass": "toast-top-right",
    "timeOut": "2500",
    "closeButton": true,
    "showEasing": "swing",
    "hideEasing": "linear",
    "showMethod": "fadeIn",
    "hideMethod": "fadeOut"
};

$(function () {
    $(".btn-primary").on("click", function (event) {
        let actionType = $(this).data("action");
        let userNameInput = $("#username");
        let messageSpan = $("#message");
        let username = userNameInput.val();

        if (!isValidInput(username)) {
            messageSpan.text("Invalid username");
            return;
        }

        userNameInput.prop("readonly", true);
        messageSpan.text("");

        let button = event.target;
        let previousText = button.innerHTML;
        disableButton(button);

        (actionType === "register" ? requestCreateCredentialOptions(username) : requestVerifyCredentialOptions(username))
            .finally(() => {
                userNameInput.prop("readonly", false);
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