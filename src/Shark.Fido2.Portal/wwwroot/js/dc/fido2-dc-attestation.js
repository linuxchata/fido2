// Registration

const registrationTitle = 'Web Authentication';

async function requestCreateDiscoverableCredentialOptions(username, displayName) {
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

    const options = await fetchAttestationOptions(optionsRequest);

    await createCredential(options);
}

async function createCredential(options) {
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
            challenge: toUint8Array(options.challenge),
            excludeCredentials: options.excludeCredentials.map(credential => ({
                id: toUint8Array(credential.id),
                transports: credential.transports,
                type: credential.type,
            })),
            timeout: options.timeout,
            attestation: options.attestation
        },
    };

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

    const credentials = {
        id: attestation.id,
        rawId: toBase64Url(attestation.rawId),
        response: {
            attestationObject: toBase64Url(attestation.response.attestationObject),
            clientDataJson: toBase64Url(attestation.response.clientDataJSON),
            transports: attestation.response.getTransports(),
        },
        type: attestation.type,
    };

    await fetchAttestationResult(credentials);
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
            notify.error("Error creating registration options", registrationTitle);
        }
    } catch (error) {
        notify.error(error.message, registrationTitle);
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
            notify.error(`Registration has failed. ${responseBody.errorMessage}`, registrationTitle);
        }
    } catch (error) {
        notify.error(error.message, registrationTitle);
    }
}

window.requestCreateDiscoverableCredentialOptions = requestCreateDiscoverableCredentialOptions;