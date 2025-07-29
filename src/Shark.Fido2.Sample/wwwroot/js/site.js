$(function () {
    $("#register").on("click", function (event) {
        const usernameInput = $("#username-register");
        const displayNameInput = $("#display-name-register");
        const errorMessageSpan = $("#error-message-register");
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

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const pageValue = $('[data-page]').data('page');
        if (pageValue === 'non-discoverable-credentials') {
            const optionsRequest = {
                username: username,
                displayName: displayName,
                attestation: 'direct',
                authenticatorSelection: {
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                    requireResidentKey: false
                }
            };

            requestCreateCredentialOptions(optionsRequest)
                .finally(() => {
                    usernameInput.prop("readonly", false);
                    displayNameInput.prop("readonly", false);
                    enableButton(button, previousText);
                });
        }
        else if (pageValue === 'custom-credentials') {
            const userVerificationSelect = $("#user-verification-register");
            const attachmentSelect = $("#attachment-register");
            const residentKeySelect = $("#resident-key-register");
            const attestationSelect = $("#attestation-register");
            const userVerification = userVerificationSelect.val();
            const attachment = attachmentSelect.val();
            const residentKey = residentKeySelect.val();
            const attestation = attestationSelect.val();

            userVerificationSelect.prop("disabled", true);
            attachmentSelect.prop("disabled", true);
            residentKeySelect.prop("disabled", true);
            attestationSelect.prop("disabled", true);

            const optionsRequest = {
                username: username,
                displayName: displayName,
                attestation: attestation,
                authenticatorSelection: {
                    residentKey: residentKey,
                    userVerification: userVerification,
                    requireResidentKey: residentKey === 'required',
                    authenticatorAttachment: attachment || null
                }
            };

            requestCreateCredentialOptions(optionsRequest)
                .finally(() => {
                    usernameInput.prop("readonly", false);
                    displayNameInput.prop("readonly", false);
                    userVerificationSelect.prop("disabled", false);
                    attachmentSelect.prop("disabled", false);
                    residentKeySelect.prop("disabled", false);
                    attestationSelect.prop("disabled", false);
                    enableButton(button, previousText);
                });
        }
    });

    $("#authenticate").on("click", function (event) {
        const usernameInput = $("#username-authenticate");
        const errorMessageSpan = $("#error-message-authenticate");
        const username = usernameInput.val();

        if (!isValidInput(username)) {
            errorMessageSpan.text("Please input a username");
            return;
        }

        usernameInput.prop("readonly", true);
        errorMessageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const pageValue = $('[data-page]').data('page');
        if (pageValue === 'non-discoverable-credentials') {
            const optionsRequest = {
                username: username
            };

            requestVerifyCredentialOptions(optionsRequest)
                .finally(() => {
                    usernameInput.prop("readonly", false);
                    enableButton(button, previousText);
                });
        }
        else if (pageValue === 'custom-credentials') {
            const userVerificationSelect = $("#user-verification-authenticate");
            const userVerification = userVerificationSelect.val();

            userVerificationSelect.prop("disabled", true);

            const optionsRequest = {
                username: username,
                userVerification: userVerification
            };

            requestVerifyCredentialOptions(optionsRequest)
                .finally(() => {
                    usernameInput.prop("readonly", false);
                    userVerificationSelect.prop("disabled", false);
                    enableButton(button, previousText);
                });
        }
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
