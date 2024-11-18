var createLink = document.getElementById('credential-create');
if (createLink != null) {
    createLink.addEventListener('click', credentialCreateClick);
}

async function credentialCreateClick(event) {
    const response = await fetchCreadentialsCreateInitialize();

    await credentialCreate(response, 'localhost');
}

async function fetchCreadentialsCreateInitialize() {
    try {
        const response = await fetch('/creadentialcreate/initialize/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            }
        });

        if (response.ok) {
            return await response.text();
        }
    } catch (error) {
        console.error(error);
    }
}

async function credentialCreate(challenge, relyingPartyIdentifier) {
    const credentialCreationOptions = {
        publicKey: {
            challenge: new Uint8Array(challenge),
            rp: {
                name: "Example CORP",
                id: relyingPartyIdentifier,
            },
            user: {
                id: new Uint8Array(16),
                name: "canand@example.com",
                displayName: "Carina Anand",
            },
            pubKeyCredParams: [
                {
                    type: "public-key",
                    alg: -7, // ES256
                },
            ],
        },
    };

    navigator.credentials
        .create(credentialCreationOptions)
        .then(function (assertion) {
            // Send assertion to server for verification
        }).catch(function (error) {
            console.error(error);
        });
}

window.credentialCreateClick = credentialCreateClick;