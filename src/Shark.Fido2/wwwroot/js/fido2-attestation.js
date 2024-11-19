var createLink = document.getElementById('credential-create');
if (createLink != null) {
    createLink.addEventListener('click', credentialCreateClick);
}

async function credentialCreateClick(event) {
    const response = await fetchCreadentialsCreateInitialize();

    await credentialCreate(response);
}

async function fetchCreadentialsCreateInitialize() {
    try {
        const response = await fetch('/attestation/options/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            }
        });

        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error(error);
    }
}

async function credentialCreate(response) {
    const credentialCreationOptions = {
        publicKey: {
            challenge: base64ToUint8Array(response.challenge),
            rp: {
                id: response.rp.id,
                name: response.rp.name,
            },
            user: {
                id: base64ToUint8Array(response.challenge),
                name: response.user.name,
                displayName: response.user.displayName,
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

function base64ToUint8Array(base64) {
    // Decode the Base64 string to a binary string
    const binaryString = atob(base64);

    // Create a Uint8Array and fill it with the character codes
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }

    return uint8Array;
}

window.credentialCreateClick = credentialCreateClick;