// Registration of a public key credential using the Web Authentication API

const registrationTitle = 'Web Authentication';

async function registration(username, displayName) {
    const optionsRequest = {
        username: username,
        displayName: displayName,
        attestation: 'direct',
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
            requireResidentKey: false
        }
    };

    await registrationCustom(optionsRequest);
}

async function registrationOfDiscoverableCredential(username, displayName) {
    const optionsRequest = {
        username: username,
        displayName: displayName,
        attestation: 'direct',
        authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'required',
            requireResidentKey: true
        }
    };

    await registrationCustom(optionsRequest);
}

async function registrationCustom(optionsRequest) {
    console.log("Start fetching attestation options");

    const options = await fetchAttestationOptions(optionsRequest);

    console.log(`Server side attestation options\n${JSON.stringify(options)}`);

    await createCredential(options);
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

    console.log(`Mapped attestation options\n${JSON.stringify(credentialCreationOptions)}`);

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

    console.log("Attestation object was received from browser");

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

    console.log(`Mapped attestation object ${JSON.stringify(credentials)}`);

    await fetchAttestationResult(credentials);

    console.log("Attestation was completed on server side");
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
        notify.error("Error creating registration options", registrationTitle);
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
            notify.info('Registration was successful', registrationTitle);
        }
        else {
            const responseBody = await response.json();
            throw new Error(responseBody.errorMessage);
        }
    } catch (error) {
        notify.error(`Registration has failed. ${error.message}`, registrationTitle);
    }
}

window.registration = registration;
window.registrationOfDiscoverableCredential = registrationOfDiscoverableCredential;
window.registrationCustom = registrationCustom;
