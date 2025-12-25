// Combined FIDO2 registration and authentication logic

async function register() {
    const username = document.getElementById('username-registration').value;
    const displayName = document.getElementById('display-name-registration').value;
    const errorSpan = document.getElementById('error-message-registration');
    const btn = document.getElementById('btn-register');

    if (!username || !displayName) {
        errorSpan.innerText = 'Please enter both username and display name.';
        return;
    }

    errorSpan.innerText = '';
    setLoading(btn, true);

    try {
        const optionsResponse = await fetch('/attestation/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, displayName })
        });

        if (!optionsResponse.ok) throw new Error('Failed to get registration options');
        const options = await optionsResponse.json();

        const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options);
        const attestation = await navigator.credentials.create({ publicKey });

        const resultResponse = await fetch('/attestation/result', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attestation)
        });

        if (resultResponse.ok) {
            alert('Registration successful!');
        } else {
            const error = await resultResponse.json();
            throw new Error(error.errorMessage || 'Registration failed');
        }
    } catch (err) {
        errorSpan.innerText = err.message;
    } finally {
        setLoading(btn, false);
    }
}

async function authenticate() {
    const username = document.getElementById('username-authentication').value;
    const errorSpan = document.getElementById('error-message-authentication');
    const btn = document.getElementById('btn-authenticate');

    if (!username) {
        errorSpan.innerText = 'Please enter your username.';
        return;
    }

    errorSpan.innerText = '';
    setLoading(btn, true);

    try {
        const optionsResponse = await fetch('/assertion/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!optionsResponse.ok) throw new Error('Failed to get authentication options');
        const options = await optionsResponse.json();

        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options);
        const assertion = await navigator.credentials.get({ publicKey });

        const resultResponse = await fetch('/assertion/result', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertion)
        });

        if (resultResponse.ok) {
            alert('Authentication successful!');
        } else {
            const error = await resultResponse.json();
            throw new Error(error.errorMessage || 'Authentication failed');
        }
    } catch (err) {
        errorSpan.innerText = err.message;
    } finally {
        setLoading(btn, false);
    }
}

function setLoading(btn, loading) {
    btn.disabled = loading;
    btn.innerHTML = loading ? 'Processing...' : (btn.id === 'btn-register' ? 'Register' : 'Authenticate');
}

window.register = register;
window.authenticate = authenticate;
