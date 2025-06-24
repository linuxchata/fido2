document.addEventListener('DOMContentLoaded', () => {
    const getById = (id) => document.getElementById(id);

    const signUpUserNameInput = getById('signUpUserName');
    const signUpDisplayNameInput = getById('signUpDisplayName');
    const signUpButton = getById('signUpButton');

    const signInUserNameInput = getById('signInIdentifier');
    const signInButton = getById('signInButton');

    const credentialIdInput = getById('credentialId');
    const credentialsButton = getById('credentialsButton');

    async function handleAsyncAction(button, asyncAction, originalText) {
        button.disabled = true;
        button.textContent = 'Processing...';
        try {
            await asyncAction();
        } finally {
            button.disabled = false;
            button.textContent = originalText;
        }
    }

    function toggleCredentialsButtonVisibility() {
        if (credentialsButton && credentialIdInput) {
            credentialsButton.classList.toggle('hide', !credentialIdInput.value);
        }
    }

    if (signUpButton) {
        signUpButton.addEventListener('click', async function () {
            const userName = signUpUserNameInput?.value;
            const displayName = signUpDisplayNameInput?.value;

            if (!userName || !displayName) {
                notify.error('Please fill in all required fields', 'Validation Error');
                return;
            }

            await handleAsyncAction(
                this,
                () => requestCreateCredentialOptions(userName, displayName),
                this.textContent
            );
        });
    }

    if (signInButton) {
        signInButton.addEventListener('click', async function () {
            if (credentialIdInput) {
                credentialIdInput.value = '';
            }

            const userName = signInUserNameInput?.value;

            await handleAsyncAction(
                this,
                () => requestVerifyCredentialOptions(userName),
                this.textContent
            );

            toggleCredentialsButtonVisibility();
        });
    }

    if (credentialsButton) {
        credentialsButton.addEventListener('click', () => {
            if (credentialIdInput) {
                const credentialId = credentialIdInput?.value;

                if (credentialId) {
                    window.location.href = `/CredentialsDetails?credentialId=${encodeURIComponent(credentialId)}`;
                }
            }
        });
    }
});