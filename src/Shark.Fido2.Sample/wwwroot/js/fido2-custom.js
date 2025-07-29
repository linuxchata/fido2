// Custom WebAuthn configuration page

const registrationTitle = 'Web Authentication - Custom';
const authenticationTitle = 'Web Authentication - Custom';

async function requestCreateCredentialOptions(username, displayName) {
    // Read dropdown values from the Custom page
    const userVerification = document.getElementById('user-verification-register').value;
    const attachment = document.getElementById('attachment-register').value;
    const residentKey = document.getElementById('resident-key-register').value;
    const attestation = document.getElementById('attestation-register').value;

    const optionsRequest = {
        username: username,
        displayName: displayName,
        attestation: attestation,
        authenticatorSelection: {
            residentKey: residentKey,
            userVerification: userVerification,
            requireResidentKey: residentKey === 'required',
            authenticatorAttachment: attachment || null
        }
    };

    console.log("Start fetching custom attestation options");

    const options = await fetchAttestationOptions(optionsRequest);

    console.log(`Server side custom attestation options\n${JSON.stringify(options)}`);

    await createCredential(options);
}

async function requestVerifyCredentialOptions(username) {
    // Read dropdown values from the Custom page
    const userVerification = document.getElementById('user-verification-authenticate').value;

    const optionsRequest = {
        username: username,
        userVerification: userVerification
    };

    console.log("Start fetching custom assertion options");

    const options = await fetchAssertionOptions(optionsRequest);

    console.log(`Server side custom assertion options\n${JSON.stringify(options)}`);

    await requestCredential(options);
}

async function createCredential(options) {
    let extensions = {
        ...(options.extensions.appidExclude && { appidExclude: options.extensions.appidExclude }),
        ...(options.extensions.uvm && { uvm: options.extensions.uvm }),
        ...(options.extensions.credProps && { credProps: options.extensions.credProps }),
        ...(options.extensions.largeBlob && { largeBlob: options.extensions.largeBlob })
    };

    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
    const credentialCreationOptions = {
        publicKey: {
            rp: {
                id: options.rp.id,
                name: options.rp.name,
            },
            user: {
                id: toUint8Array(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            pubKeyCredParams: options.pubKeyCredParams.map(param => ({
                type: param.type,
                alg: param.alg,
            })),
            authenticatorSelection: options.authenticatorSelection,
            challenge: toUint8Array(options.challenge),
            excludeCredentials: options.excludeCredentials.map(credential => ({
                id: toUint8Array(credential.id),
                transports: credential.transports,
                type: credential.type,
            })),
            timeout: options.timeout,
            attestation: options.attestation,
            extensions: extensions
        },
    };

    console.log(`Mapped custom attestation options\n${JSON.stringify(credentialCreationOptions)}`);

    let attestation;
    try {
        attestation = await navigator.credentials.create(credentialCreationOptions);
    }
    catch (error) {
        if (error.name === 'InvalidStateError') {
            notify.error('The authenticator was not allowed because it was already registered.', registrationTitle);
        }
        else {
            notify.error(error.message, registrationTitle);
        }
        return;
    }

    console.log("Custom attestation object was received from browser");

    const credentials = {
        id: attestation.id,
        rawId: toBase64Url(attestation.rawId),
        response: {
            attestationObject: toBase64Url(attestation.response.attestationObject),
            clientDataJson: toBase64Url(attestation.response.clientDataJSON),
            transports: attestation.response.getTransports(),
        },
        type: attestation.type,
        extensions: attestation.getClientExtensionResults(),
    };

    console.log(`Mapped custom attestation object ${JSON.stringify(credentials)}`);

    await fetchAttestationResult(credentials);

    console.log("Custom attestation was completed on server side");
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

    console.log(`Mapped custom assertion options\n${JSON.stringify(credentialRequestOptions)}`);

    let assertion;
    try {
        assertion = await navigator.credentials.get(credentialRequestOptions);
    }
    catch (error) {
        notify.error(error.message, authenticationTitle);
        return;
    }

    console.log("Custom assertion object was received from browser");

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

    console.log(`Mapped custom assertion object ${JSON.stringify(credentials)}`);

    await fetchAssertionResult(credentials);

    console.log("Custom assertion was completed on server side");
}

async function fetchAttestationOptions(optionsRequest) {
    try {
        const response = await fetch('/attestation/options/', {
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
        notify.error("Error creating custom registration options", registrationTitle);
        throw error;
    }
}

async function fetchAttestationResult(credentials) {
    try {
        const response = await fetch('/attestation/result/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        if (response.ok) {
            notify.success('Registration completed successfully!', registrationTitle);
        }
        else {
            const errorMessage = await response.text();
            throw new Error(`Server responded with status code ${response.status}: ${errorMessage}`);
        }
    } catch (error) {
        notify.error("Error completing custom registration", registrationTitle);
        throw error;
    }
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
        notify.error("Error creating custom authentication options", authenticationTitle);
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
            notify.success('Authentication completed successfully!', authenticationTitle);
        }
        else {
            const errorMessage = await response.text();
            throw new Error(`Server responded with status code ${response.status}: ${errorMessage}`);
        }
    } catch (error) {
        notify.error("Error completing custom authentication", authenticationTitle);
        throw error;
    }
} 