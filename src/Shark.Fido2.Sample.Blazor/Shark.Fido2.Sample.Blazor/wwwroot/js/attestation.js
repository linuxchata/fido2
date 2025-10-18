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

async function registrationCustom(optionsRequest) {
    console.log("Start fetching attestation options");

    const options = await fetchAttestationOptions(optionsRequest);

    console.log(`Server side attestation options\n${JSON.stringify(options)}`);

    await createCredential(options);
}

async function createCredential(options) {
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options);

    console.log(`Mapped attestation options\n${JSON.stringify(publicKey)}`);

    let attestation;
    try {
        attestation = await navigator.credentials.create({ publicKey });
    }
    catch (error) {
        console.error(error.message);
        if (error.name === 'InvalidStateError') {
            notify.error('The authenticator was not allowed because it was already registered.', registrationTitle);
        }
        else {
            notify.error(error.message, registrationTitle);
        }
        return;
    }

    console.log("Attestation object was received from browser");
    console.log(`Mapped attestation object ${JSON.stringify(attestation)}`);

    await fetchAttestationResult(attestation);

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
        console.error(error.message);
        notify.error("Error creating registration options", registrationTitle);
        throw error;
    }
}

async function fetchAttestationResult(attestation) {
    try {
        const response = await fetch('/attestation/result/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(attestation) // Calls toJSON() method
        });

        if (response.ok) {
            window.location.href = 'signin'
        }
        else {
            const responseBody = await response.json();
            throw new Error(responseBody.errorMessage ?? responseBody.title);
        }
    } catch (error) {
        console.error(error.message);
        notify.error(`Sign-up failed. ${error.message}`, registrationTitle);
    }
}

window.registration = registration;