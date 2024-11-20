var createLink = document.getElementById('credential-create');
if (createLink != null) {
    createLink.addEventListener('click', credentialCreateClick);
}

async function credentialCreateClick(event) {
    const response = await fetchAttestationOptions();

    await credentialCreate(response);
}

async function fetchAttestationOptions() {
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

async function fetchAttestationResult(request) {
    try {
        const response = await fetch('/attestation/result/', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(request)
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
            challenge: toUint8Array(response.challenge),
            rp: {
                id: response.rp.id,
                name: response.rp.name,
            },
            user: {
                id: toUint8Array(response.challenge),
                name: response.user.name,
                displayName: response.user.displayName,
            },
            pubKeyCredParams: [
                {
                    type: "public-key",
                    alg: -257, // RS256
                },
                {
                    type: "public-key",
                    alg: -7, // ES256
                },
            ],
            attestation: "direct"
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

function toUint8Array(base64) {
    // Decode the Base64 string to a binary string
    const binaryString = atob(base64);

    // Create a Uint8Array and fill it with the character codes
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }

    return uint8Array;
}

function toBase64(uint8Array) {
    // Convert Uint8Array to a binary string
    const binaryString = String.fromCharCode.apply(null, new Uint8Array(uint8Array));

    // Encode the binary string to Base64
    return btoa(binaryString);
}

window.credentialCreateClick = credentialCreateClick;