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

        setInputsReadonly([usernameInput, displayNameInput], true);
        errorMessageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const pageValue = $("[data-page]").data("page");
        if (pageValue === "non-discoverable-credentials") {
            const optionsRequest = buildNonDiscoverableCredentialsRegistrationOptions(username, displayName);
            registration(optionsRequest)
                .finally(() => {
                    setInputsReadonly([usernameInput, displayNameInput], false);
                    enableButton(button, previousText);
                });
        } else if (pageValue === "custom-credentials") {
            const selects = [
                $("#user-verification-registration"),
                $("#attachment-registration"),
                $("#resident-key-registration"),
                $("#attestation-registration")
            ];
            const optionsRequest = buildCustomCredentialsRegistrationOptions(username, displayName, selects);
            setSelectsDisabled(selects, true);
            registration(optionsRequest)
                .finally(() => {
                    setInputsReadonly([usernameInput, displayNameInput], false);
                    setSelectsDisabled(selects, false);
                    enableButton(button, previousText);
                });
        }
    });

    $("#authentication").on("click", function (event) {
        const usernameInput = $("#username-authentication");
        const errorMessageSpan = $("#error-message-authentication");
        const username = usernameInput.val();

        if (!isValidInput(username)) {
            errorMessageSpan.text("Please input a username");
            return;
        }

        setInputsReadonly([usernameInput], true);
        errorMessageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const pageValue = $("[data-page]").data("page");
        if (pageValue === "non-discoverable-credentials") {
            const optionsRequest = buildNonDiscoverableCredentialsAuthenticationOptions(username);
            authentication(optionsRequest)
                .finally(() => {
                    setInputsReadonly([usernameInput], false);
                    enableButton(button, previousText);
                });
        } else if (pageValue === "custom-credentials") {
            const selects = [$("#user-verification-authentication")];
            const optionsRequest = buildCustomCredentialsAuthenticationOptions(username, selects);
            setSelectsDisabled(selects, true);
            authentication(optionsRequest)
                .finally(() => {
                    setInputsReadonly([usernameInput], false);
                    setSelectsDisabled(selects, false);
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

function setInputsReadonly(inputs, readonly) {
    inputs.forEach(input => input.prop("readonly", readonly));
}

function setSelectsDisabled(selects, disabled) {
    selects.forEach(select => select.prop("disabled", disabled));
}

function buildNonDiscoverableCredentialsRegistrationOptions(username, displayName) {
    return {
        username: username,
        displayName: displayName,
        attestation: 'direct',
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
            requireResidentKey: false
        }
    };
}

function buildNonDiscoverableCredentialsAuthenticationOptions(username) {
    return { username };
}

function buildCustomCredentialsRegistrationOptions(username, displayName, selects) {
    const [userVerificationSelect, attachmentSelect, residentKeySelect, attestationSelect] = selects;
    return {
        username: username,
        displayName: displayName,
        attestation: attestationSelect.val(),
        authenticatorSelection: {
            residentKey: residentKeySelect.val(),
            userVerification: userVerificationSelect.val(),
            requireResidentKey: residentKeySelect.val() === 'required',
            authenticatorAttachment: attachmentSelect.val() || null
        }
    };
}

function buildCustomCredentialsAuthenticationOptions(username, selects) {
    const [userVerificationSelect] = selects;
    return {
        username: username,
        userVerification: userVerificationSelect.val()
    };
}
