﻿// Registration

const toastrRegistrationTitle = 'Web Authentication';

async function requestCreateCredentialOptions(username, displayName) {
    const optionsRequest = {
        username: username,
        displayName: displayName,
        attestation: 'direct',
        authenticatorSelection: { userVerification: 'required' }
    };

    const options = await fetchAttestationOptions(optionsRequest);

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

    let attestation;
    try {
        attestation = await navigator.credentials.create(credentialCreationOptions);
    }
    catch (error) {
        toastr.error(error.message, toastrRegistrationTitle);
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
        else {
            const errorMessage = await response.text();
            throw new Error(`Server responded with status code ${response.status}: ${errorMessage}`);
        }
    } catch (error) {
        toastr.error("Error creating registration options", toastrRegistrationTitle);
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
            toastr.info('Registration was successful', toastrRegistrationTitle);
        }
        else {
            const responseBody = await response.json();
            throw new Error(responseBody.errorMessage);
        }
    } catch (error) {
        toastr.error(`Registration has failed. ${error.message}`, toastrRegistrationTitle);
    }
}

window.requestCreateCredentialOptions = requestCreateCredentialOptions;