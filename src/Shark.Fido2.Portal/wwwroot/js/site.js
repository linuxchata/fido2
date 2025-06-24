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

    function toggleCredentialsButtonVisibility() {
        const credentialsButton = getById('credentialsButton');
        const credentialIdInput = getById('credentialId');

        if (credentialsButton && credentialIdInput) {
            credentialsButton.classList.toggle('hide', !credentialIdInput.value);
        }
    }

    const signupButton = getById('signupButton');
    if (signupButton) {
        signupButton.addEventListener('click', async function () {
            const username = getById('signupUsername')?.value;
            const displayName = getById('signupDisplayName')?.value;

            if (!username || !displayName) {
                notify.error('Please fill in all required fields', 'Validation Error');
                return;
            }

            await handleAsyncAction(
                this,
                () => requestCreateCredentialOptions(username, displayName),
                this.textContent
            );
        });
    }

    const signinButton = getById('signinButton');
    if (signinButton) {
        signinButton.addEventListener('click', async function () {
            const credentialIdInput = getById('credentialId');
            if (credentialIdInput) {
                 credentialIdInput.value = '';
            }

            toggleCredentialsButtonVisibility();

            const username = getById('signinUsername')?.value;

            await handleAsyncAction(
                this,
                () => requestVerifyCredentialOptions(username),
                this.textContent
            );

            toggleCredentialsButtonVisibility();
        });
    }

    const credentialsButton = getById('credentialsButton');
    if (credentialsButton) {
        credentialsButton.addEventListener('click', () => {
            const credentialIdInput = getById('credentialId');
            const credentialId = credentialIdInput?.value;
            if (credentialIdInput) {
                credentialIdInput.value = '';
                toggleCredentialsButtonVisibility();
            }

            if (credentialId) {
                window.location.href = `/CredentialsDetails?credentialId=${encodeURIComponent(credentialId)}`;
            }
        });
    }
});