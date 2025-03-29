// Registration

async function requestCreateCredentialOptions() {
    const optionsRequest = {
        username: 'HNAiCzKv7VHrICaBeeFZ',
        displayName: 'Shark',
        attestation: 'direct'
    };

    const options = await fetchAttestationOptions(optionsRequest);

    await createCredential(options);
}

async function createCredential(options) {
    const extensions = options.extensions.credProps ? { 'credProps': options.extensions.credProps } : {};

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
            timeout: options.timeout,
            attestation: options.attestation,
            extensions: extensions
        },
    };

    let attestation;
    try {
        attestation = await navigator.credentials.create(credentialCreationOptions);
    }
    catch (error) {
        toastr.error(error, 'Web Authentication');
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
        extensions: attestation.getClientExtensionResults(),
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
    } catch (error) {
        toastr.error(error, 'Web Authentication');
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
            toastr.info('Registration was successful', 'Web Authentication');
        }
    } catch (error) {
        toastr.error(error, 'Web Authentication');
    }
}

window.requestCreateCredentialOptions = requestCreateCredentialOptions;