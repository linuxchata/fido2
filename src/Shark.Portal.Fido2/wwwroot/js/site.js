document.addEventListener('DOMContentLoaded', function () {
    // Sign up button event listener
    document.getElementById('signupButton').addEventListener('click', function () {
        const username = document.getElementById('signupUsername').value;
        const displayName = document.getElementById('displayName').value;

        if (username && displayName) {
            requestCreateCredentialOptions(username, displayName);
        } else {
            notify.error('Please fill in all required fields', 'Validation Error');
        }
    });

    // Sign in button event listener
    document.getElementById('signinButton').addEventListener('click', function () {
        const username = document.getElementById('signinUsername').value;

        if (username) {
            requestVerifyCredentialOptions(username);
        } else {
            notify.error('Please enter your username', 'Validation Error');
        }
    });
});
