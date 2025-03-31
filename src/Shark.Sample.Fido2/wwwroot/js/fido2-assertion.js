// Authentication

const toastrAuthenticationTitle = 'Web Authentication';

async function requestVerifyCredentialOptions(username) {
    const optionsRequest = {
        username: username
    };

    const options = await fetchAssertionOptions(optionsRequest);

    await requestCredential(options);
}

async function requestCredential(options) {
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
        toastr.error(error.message, toastrAuthenticationTitle);
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
            toastr.error("Error creating authentication options", toastrAuthenticationTitle);
        }
    } catch (error) {
        toastr.error(error.message, toastrAuthenticationTitle);
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
            toastr.info('Authentication was successful', toastrAuthenticationTitle);
        }
        else {
            toastr.error("Authentication has failed", toastrAuthenticationTitle);
        }
    } catch (error) {
        toastr.error(error.message, toastrAuthenticationTitle);
    }
}

window.requestVerifyCredentialOptions = requestVerifyCredentialOptions;