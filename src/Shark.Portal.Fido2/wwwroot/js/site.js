document.addEventListener('DOMContentLoaded', function () {
    async function handleAsyncAction(button, asyncAction, originalText) {
        button.disabled = true;
        button.textContent = 'Processing...';

        await asyncAction();

        button.disabled = false;
        button.textContent = originalText;
    }

    // Sign up button event listener
    document.getElementById('signupButton').addEventListener('click', async function () {
        const originalText = this.textContent; // this is the button
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

    // Sign in button event listener
    document.getElementById('signinButton').addEventListener('click', async function () {
        const originalText = this.textContent; // this is the button
        const username = document.getElementById('signinUsername').value;

        await handleAsyncAction(
            this,
            () => requestVerifyCredentialOptions(username),
            originalText
        );
    });
});
