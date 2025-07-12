// Authentication

const authenticationTitle = 'Web Authentication';

async function requestVerifyDiscoverableCredentialOptions() {
    const optionsRequest = { };

    const options = await fetchAssertionOptions(optionsRequest);

    await requestCredential(options);
}

async function requestCredential(options) {
    const credentialRequestOptions = {
        publicKey: {
            rpId: options.rpId,
            challenge: toUint8Array(options.challenge),
            allowCredentials: [],
            timeout: options.timeout
        },
    };

    let assertion;
    try {
        assertion = await navigator.credentials.get(credentialRequestOptions);
    }
    catch (error) {
        notify.error(error.message, authenticationTitle);
        return;
    }

    const credentials = {
        id: assertion.id,
        rawId: toBase64Url(assertion.rawId),
        response: {
            authenticatorData: toBase64Url(assertion.response.authenticatorData),
            clientDataJson: toBase64Url(assertion.response.clientDataJSON),
            signature: toBase64Url(assertion.response.signature),
            userHandle: toBase64Url(assertion.response.userHandle),
        },
        type: assertion.type,
    };

    await fetchAssertionResult(credentials);
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
        else {
            notify.error("Error creating authentication options", authenticationTitle);
        }
    } catch (error) {
        notify.error(error.message, authenticationTitle);
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
            document.getElementById('credentialId').value = credentials.id;
            notify.info('Authentication was successful', authenticationTitle);
        }
        else {
            const responseBody = await response.json();
            notify.error(`Authentication has failed. ${responseBody.errorMessage}`, authenticationTitle);
        }
    } catch (error) {
        notify.error(error.message, authenticationTitle);
    }
}

window.requestVerifyDiscoverableCredentialOptions = requestVerifyDiscoverableCredentialOptions;