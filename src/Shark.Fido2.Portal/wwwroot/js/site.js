document.addEventListener('DOMContentLoaded', () => {
    const getById = (id) => document.getElementById(id);

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

    const credentialIdInput = getById('credentialId');
    const credentialsButton = getById('credentialsButton');

    function toggleCredentialsButtonVisibility() {
        if (credentialsButton && credentialIdInput) {
            credentialsButton.classList.toggle('hide', !credentialIdInput.value);
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
                () => requestCreateCredentialOptions(userName, displayName),
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

            const signInUserNameInput = getById('signInUserName');
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
                    window.location.href = `/CredentialDetails?credentialId=${encodeURIComponent(credentialId)}`;
                }
            }
        });
    }
});