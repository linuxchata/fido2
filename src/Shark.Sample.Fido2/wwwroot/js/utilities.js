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