document.addEventListener('DOMContentLoaded', function () {
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

    // Credential details button
    function toggleCredentialDetailsButton() {
        const credentialDetailsButton = document.getElementById('credentialDetailsButton');

        if (credentialDetailsButton) {
            const credentialIdInput = document.getElementById('credentialId');

            if (credentialIdInput) {
                if (credentialIdInput.value) {
                    credentialDetailsButton.classList.remove('hide');
                }
                else {
                    credentialDetailsButton.classList.add('hide');
                }
            }
            else {
                credentialDetailsButton.classList.add('hide');
            }
        }
    }

    // Sign up button event listener
    var signupButton = document.getElementById('signupButton');
    if (signupButton && signupButton.addEventListener) {
        signupButton.addEventListener('click', async function () {
            const originalText = this.textContent; // 'this' is the button
            const username = document.getElementById('signupUsername').value;
            const displayName = document.getElementById('displayName').value;

            if (username && displayName) {
                await handleAsyncAction(
                    this,
                    () => requestCreateCredentialOptions(username, displayName),
                    originalText
                );
            } else {
                notify.error('Please fill in all required fields', 'Validation Error');
            }
        });
    }

    // Sign in button event listener
    var signinButton = document.getElementById('signinButton');
    if (signinButton && signinButton.addEventListener) {
        signinButton.addEventListener('click', async function () {
            const originalText = this.textContent; // 'this' is the button
            const username = document.getElementById('signinUsername').value;

            await handleAsyncAction(
                this,
                () => requestVerifyCredentialOptions(username),
                originalText
            );

            toggleCredentialDetailsButton();
        });
    }

    // Credential details button event listener
    var credentialDetailsButton = document.getElementById('credentialDetailsButton');
    if (credentialDetailsButton && signinButton.addEventListener) {
        credentialDetailsButton.addEventListener('click', function () {
            window.location.href = '/CredentialsDetails?credentialId=' + document.getElementById('credentialId').value
        });
    }
});
