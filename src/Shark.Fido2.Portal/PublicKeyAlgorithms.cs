namespace Shark.Fido2.Portal;

public static class PublicKeyAlgorithms
{
    private readonly static Dictionary<string, int> _algorithms = new Dictionary<string, int>
    {
        { "ES256 (ECDSA w/ SHA-256)", -7 },
        { "EdDSA (EdDSA)", -8 },
        { "ES384 (ECDSA w/ SHA-384)", -35 },
        { "ES512 (ECDSA w/ SHA-512)", -36 },
        { "PS256 (RSASSA-PSS w/ SHA-256)", -37 },
        { "PS384 (RSASSA-PSS w/ SHA-384)", -38 },
        { "PS512 (RSASSA-PSS w/ SHA-512)", -39 },
        { "ES256K (ECDSA using secp256k1 curve and SHA-256)", -47 },
        { "RS256 (RSASSA-PKCS1-v1_5 using SHA-256)", -257 },
        { "RS384 (RSASSA-PKCS1-v1_5 using SHA-384)", -258 },
        { "RS512 (RSASSA-PKCS1-v1_5 using SHA-512)", -259 },
        { "RS1 (RSASSA-PKCS1-v1_5 using SHA-1)", -65535 }
    };

    public static string Get(int value)
    {
        return _algorithms.FirstOrDefault(x => x.Value == value).Key ?? "Unknown Algorithm";
    }
}
