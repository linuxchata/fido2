namespace Shark.Fido2.Portal;

public static class PublicKeyAlgorithms
{
    private readonly static Dictionary<int, string> _algorithms = new()
    {
        { -7, "ES256 (ECDSA w/ SHA-256)" },
        { -8, "EdDSA (EdDSA)" },
        { -35, "ES384 (ECDSA w/ SHA-384)" },
        { -36, "ES512 (ECDSA w/ SHA-512)" },
        { -37, "PS256 (RSASSA-PSS w/ SHA-256)" },
        { -38, "PS384 (RSASSA-PSS w/ SHA-384)" },
        { -39, "PS512 (RSASSA-PSS w/ SHA-512)" },
        { -47, "ES256K (ECDSA using secp256k1 curve and SHA-256)" },
        { -257, "RS256 (RSASSA-PKCS1-v1_5 using SHA-256)" },
        { -258, "RS384 (RSASSA-PKCS1-v1_5 using SHA-384)" },
        { -259, "RS512 (RSASSA-PKCS1-v1_5 using SHA-512)" },
        { -65535, "RS1 (RSASSA-PKCS1-v1_5 using SHA-1)" }
    };

    public static string Get(int key)
    {
        return _algorithms.FirstOrDefault(x => x.Key == key).Value ?? "Unknown";
    }
}
