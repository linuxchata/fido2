﻿// Authentication

const authenticationTitle = 'Web Authentication';

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

window.requestVerifyCredentialOptions = requestVerifyCredentialOptions;