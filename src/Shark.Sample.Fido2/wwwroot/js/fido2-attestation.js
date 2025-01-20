// Registration

var createLink = document.getElementById('credential-create');
if (createLink != null) {
    createLink.addEventListener('click', credentialCreateClick);
}

async function credentialCreateClick(event) {
    const optionsRequest = {
        username: 'shark',
        displayName: 'Shark',
        attestation: 'direct'
    };

    const options = await fetchAttestationOptions(optionsRequest);

    await credentialCreate(options);
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
        console.error(error);
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
            return await response.json();
        }
    } catch (error) {
        console.error(error);
    }
}

async function credentialCreate(options) {
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
            attestation: options.attestation
        },
    };

    let attestation;
    try {
        attestation = await navigator.credentials.create(credentialCreationOptions);
    }
    catch (error) {
        console.error(error);
        return
    }

    const credentials = {
        id: attestation.id,
        rawId: toBase64(attestation.rawId),
        response: {
            attestationObject: toBase64(attestation.response.attestationObject),
            clientDataJson: toBase64(attestation.response.clientDataJSON),
            signature: toBase64(attestation.response.signature),
            userHandler: toBase64(attestation.response.userHandler),
        },
        type: attestation.type,
    };

    await fetchAttestationResult(credentials);
}

window.credentialCreateClick = credentialCreateClick;