// Authentication

var requestLink = document.getElementById('credential-request');
if (requestLink != null) {
    requestLink.addEventListener('click', credentialRequestClick);
}

async function credentialRequestClick(event) {
    const optionsRequest = {
        username: 'HNAiCzKv7VHrICaBeeFZ'
    };

    const options = await fetchAssertionOptions(optionsRequest);

    await credentialRequest(options);
}

async function fetchAssertionOptions(optionsRequest) {
    try {
        const response = await fetch('/assertion/options/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(optionsRequest)
        });

        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error(error);
    }
}

async function fetchAssertionResult(credentials) {
    try {
        const response = await fetch('/assertion/result/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error(error);
    }
}

async function credentialRequest(options) {
    const credentialRequestOptions = {
        publicKey: {
            challenge: toUint8Array(options.challenge),
            timeout: options.timeout,
            rpId: options.rpId
        },
    };

    let assertion;
    try {
        assertion = await navigator.credentials.get(credentialRequestOptions);
    }
    catch (error) {
        console.error(error);
        return
    }

    const credentials = {
        id: assertion.id,
        rawId: toBase64(assertion.rawId),
        response: {
            authenticatorData: toBase64(assertion.response.authenticatorData),
            clientDataJson: toBase64(assertion.response.clientDataJSON),
            signature: toBase64(assertion.response.signature),
            userHandle: toBase64(assertion.response.userHandle),
        },
        type: assertion.type,
    };

    await fetchAssertionResult(credentials);
}

window.credentialRequestClick = credentialRequestClick;