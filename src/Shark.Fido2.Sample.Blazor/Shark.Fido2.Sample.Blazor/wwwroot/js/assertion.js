// Authentication with a public key credential using the Web Authentication API

const authenticationTitle = 'Web Authentication';

async function authentication(username, displayName) {
    const optionsRequest = { username };

    await authenticationCustom(optionsRequest);
}

async function authenticationCustom(optionsRequest) {
    console.log("Start fetching assertion options");

    const options = await fetchAssertionOptions(optionsRequest);

    console.log(`Server side assertion options\n${JSON.stringify(options)}`);

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

    console.log(`Mapped assertion options\n${JSON.stringify(credentialRequestOptions)}`);

    let assertion;
    try {
        assertion = await navigator.credentials.get(credentialRequestOptions);
    }
    catch (error) {
        notify.error(error.message, authenticationTitle);
        return;
    }

    console.log("Assertion object was received from browser");

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

    console.log(`Mapped assertion object ${JSON.stringify(credentials)}`);

    await fetchAssertionResult(credentials);

    console.log("Assertion was completed on server side");
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
            const errorMessage = await response.text();
            throw new Error(`Server responded with status code ${response.status}: ${errorMessage}`);
        }
    } catch (error) {
        notify.error("Error creating authentication options", authenticationTitle);
        throw error;
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
            window.location.href = `/credentialdetails?credentialId=${encodeURIComponent(credentials.id)}`;
        }
        else {
            const responseBody = await response.json();
            throw new Error(responseBody.errorMessage);
        }
    } catch (error) {
        notify.error(`Sign-in has failed. ${error.message}`, authenticationTitle);
    }
}

window.authentication = authentication;