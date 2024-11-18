async function credentialRequest(challenge, relyingPartyIdentifier) {
    const credentialRequestOptions = {
        publicKey: {
            challenge: new Uint8Array(challenge),
            rpId = relyingPartyIdentifier,
            timeout: 120000 // 2 minutes
        },
    };

    navigator.credentials
        .get(credentialRequestOptions)
        .then(function (assertion) {
            // Send assertion to server for verification
        }).catch(function (err) {
            console.error(err);
        });
}

window.credentialRequest = credentialRequest;