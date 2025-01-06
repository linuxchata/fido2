// Authentication

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

async function credentialRequest(options) {
    const credentialRequestOptions = {
        publicKey: {
            challenge: toUint8Array(options.challenge),
            timeout: options.timeout,
            rpId = options.rpId
        },
    };

    navigator.credentials
        .get(credentialRequestOptions)
        .then(function (assertion) {
            // Send assertion to server for verification
        }).catch(function (err) {
            console.error(err);
        });
}

window.credentialRequest = credentialRequest;