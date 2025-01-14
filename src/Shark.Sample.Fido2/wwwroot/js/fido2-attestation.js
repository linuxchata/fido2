﻿// Registration

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

    let assertion;
    try {
        assertion = await navigator.credentials.create(credentialCreationOptions);
    }
    catch (error) {
        console.error(error);
        return
    }

    const credentials = {
        id: assertion.id,
        rawId: toBase64(assertion.rawId),
        response: {
            attestationObject: toBase64(assertion.response.attestationObject),
            clientDataJson: toBase64(assertion.response.clientDataJSON),
            signature: toBase64(assertion.response.signature),
            userHandler: toBase64(assertion.response.userHandler),
        },
        type: assertion.type,
    };

    await fetchAttestationResult(credentials);
}

window.credentialCreateClick = credentialCreateClick;