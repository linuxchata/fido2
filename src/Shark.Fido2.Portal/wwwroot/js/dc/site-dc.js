document.addEventListener('DOMContentLoaded', () => {
    const getById = (id) => document.getElementById(id);

    if (isWebAuthnSupported()) {
        const authSection = getById('auth-dc-section');
        authSection.classList.remove('hide');
    }
    else {
        const authNotSupportedSection = getById('auth-dc-notsupported-section');
        authNotSupportedSection.classList.remove('hide');
    }

    async function handleAsyncAction(button, form, asyncAction, originalText) {
        Array.from(form.elements).forEach(el => el.disabled = true);
        button.textContent = 'Processing...';
        try {
            await asyncAction();
        } finally {
            Array.from(form.elements).forEach(el => el.disabled = false);
            button.textContent = originalText;
        }
    }

    const credentialIdInput = getById('credentialId');
    const credentialsLink = getById('credentialsLink');

    function toggleCredentialsButtonVisibility() {
        if (credentialsLink && credentialIdInput) {
            credentialsLink.classList.toggle('hide', !credentialIdInput.value);
        }
    }

    const signUpButton = getById('signUpButton');

    if (signUpButton) {
        signUpButton.addEventListener('click', async function () {
            const signUpUserNameInput = getById('signUpUserName');
            const signUpDisplayNameInput = getById('signUpDisplayName');
            const userName = signUpUserNameInput?.value;
            const displayName = signUpDisplayNameInput?.value;

            if (!userName || !displayName) {
                notify.error('Please fill in all required fields', 'Validation Error');
                return;
            }

            await handleAsyncAction(
                this,
                getById('signupForm'),
                () => requestCreateDiscoverableCredentialOptions(userName, displayName),
                this.textContent
            );
        });
    }

    const signInButton = getById('signInButton');

    if (signInButton) {
        signInButton.addEventListener('click', async function () {
            if (credentialIdInput) {
                credentialIdInput.value = '';
                toggleCredentialsButtonVisibility();
            }

            await handleAsyncAction(
                this,
                getById('signinForm'),
                () => requestVerifyDiscoverableCredentialOptions(),
                this.textContent
            );

            toggleCredentialsButtonVisibility();
        });
    }

    if (credentialsLink) {
        credentialsLink.addEventListener('click', () => {
            if (credentialIdInput) {
                const credentialId = credentialIdInput?.value;

                if (credentialId) {
                    window.location.href = `/CredentialDetails?credentialId=${encodeURIComponent(credentialId)}`;
                }
            }
        });
    }
});