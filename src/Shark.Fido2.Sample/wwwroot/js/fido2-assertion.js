// Authentication

const toastrAuthenticationTitle = 'Web Authentication';

async function requestVerifyCredentialOptions(username) {
    const optionsRequest = {
        username: username,
        userVerification: 'required'
    };

    const options = await fetchAssertionOptions(optionsRequest);

    await requestCredential(options);
}

async function requestCredential(options) {
    let extensions = {
        ...(options.extensions.appid && { appid: options.extensions.appid }),
        ...(options.extensions.uvm && { uvm: options.extensions.uvm }),
        ...(options.extensions.largeBlob && { largeBlob: options.extensions.largeBlob })
    };

    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
    const credentialRequestOptions = {
        publicKey: {
            rpId: options.rpId,
            userVerification: options.userVerification,
            challenge: toUint8Array(options.challenge),
            allowCredentials: options.allowCredentials.map(credential => ({
                id: toUint8Array(credential.id),
                transports: credential.transports,
                type: credential.type,
            })),
            timeout: options.timeout,
            extensions: extensions
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
        extensions: assertion.getClientExtensionResults(),
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
            const responseBody = await response.json();
            toastr.error(`Authentication has failed. ${responseBody.errorMessage}`, toastrAuthenticationTitle);
        }
    } catch (error) {
        toastr.error(error.message, toastrAuthenticationTitle);
    }
}

window.requestVerifyCredentialOptions = requestVerifyCredentialOptions;