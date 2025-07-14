function toUint8Array(base64Url) {
    // Decode the Base64 string to a binary string
    const binaryString = atob(base64UrlToBase64(base64Url));

    // Create a Uint8Array and fill it with the character codes
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }

    return uint8Array;
}

function toBase64Url(uint8Array) {
    // Convert Uint8Array to a binary string
    const binaryString = String.fromCharCode.apply(null, new Uint8Array(uint8Array));

    // Encode the binary string to Base64
    const base64 = btoa(binaryString);

    return base64ToBase64Url(base64);
}

function base64UrlToBase64(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    while (base64.length % 4 !== 0) {
        base64 += '=';
    }

    return base64;
}

function base64ToBase64Url(base64) {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function isWebAuthnSupported() {
    return window.PublicKeyCredential != null;
}

window.isWebAuthnSupported = isWebAuthnSupported;