// Authentication with a public key credential using the Web Authentication API

const authenticationTitle = 'Web Authentication';

async function authenticationWithDiscoverableCredential() {
    const optionsRequest = {};

    console.log("Start fetching assertion options");

    const options = await fetchAssertionOptions(optionsRequest);

    console.log(`Server side assertion options\n${JSON.stringify(options)}`);

    await requestCredential(options);
}

async function requestCredential(options) {
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options);

    console.log(`Mapped assertion options\n${JSON.stringify(publicKey)}`);

    let assertion;
    try {
        assertion = await navigator.credentials.get({ publicKey });
    }
    catch (error) {
        console.error(error.message);
        notify.error(error.message, authenticationTitle);
        return;
    }

    console.log("Assertion object was received from browser");
    console.log(`Mapped assertion object ${JSON.stringify(assertion)}`);

    await fetchAssertionResult(assertion);

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
        console.error(error.message);
        notify.error("Error creating authentication options", authenticationTitle);
        throw error;
    }
}

async function fetchAssertionResult(assertion) {
    try {
        const response = await fetch('/assertion/result/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(assertion) // Calls toJSON() method
        });

        if (response.ok) {
            window.location.href = `/CredentialDetails?credentialId=${encodeURIComponent(assertion.id)}`;
        }
        else {
            const responseBody = await response.json();
            throw new Error(responseBody.errorMessage ?? responseBody.title);
        }
    } catch (error) {
        console.error(error.message);
        notify.error(`Authentication has failed. ${error.message}`, authenticationTitle);
    }
}

window.authentication = authentication;
window.authenticationWithDiscoverableCredential = authenticationWithDiscoverableCredential;
window.authenticationCustom = authenticationCustom;
