// This code is intentionally duplicated from site.js.
// site.js is referenced in documentation, so it must remain simple and minimal.
// Any shared logic should be carefully mirrored here to avoid complexity in site.js.

$(function () {
    $("#registration-custom").on("click", function (event) {
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

        const selects = [
            $("#user-verification-registration"),
            $("#attachment-registration"),
            $("#resident-key-registration"),
            $("#attestation-registration")
        ];

        setInputsReadonly([usernameInput, displayNameInput], true);
        setSelectsDisabled(selects, true);
        errorMessageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const optionsRequest = buildRegistrationOptions(username, displayName, selects);
        registrationCustom(optionsRequest)
            .finally(() => {
                setInputsReadonly([usernameInput, displayNameInput], false);
                setSelectsDisabled(selects, false);
                enableButton(button, previousText);
            });
    });

    $("#authentication-custom").on("click", function (event) {
        const usernameInput = $("#username-authentication");
        const errorMessageSpan = $("#error-message-authentication");
        const username = usernameInput.val();

        if (!isValidInput(username)) {
            errorMessageSpan.text("Please input a username");
            return;
        }

        const selects = [$("#user-verification-authentication")];

        setInputsReadonly([usernameInput], true);
        setSelectsDisabled(selects, true);
        errorMessageSpan.text("");

        const button = event.target;
        const previousText = button.innerHTML;
        disableButton(button);

        const optionsRequest = buildAuthenticationOptions(username, selects);
        authenticationCustom(optionsRequest)
            .finally(() => {
                setInputsReadonly([usernameInput], false);
                setSelectsDisabled(selects, false);
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

function setInputsReadonly(inputs, readonly) {
    inputs.forEach(input => input.prop("readonly", readonly));
}

function setSelectsDisabled(selects, disabled) {
    selects.forEach(select => select.prop("disabled", disabled));
}

function buildRegistrationOptions(username, displayName, selects) {
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

function buildAuthenticationOptions(username, selects) {
    const [userVerificationSelect] = selects;
    return {
        username: username,
        userVerification: userVerificationSelect.val()
    };
}
