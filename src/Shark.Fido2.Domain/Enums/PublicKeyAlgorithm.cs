namespace Shark.Fido2.Domain.Enums
{
    /// <summary>
    /// COSE Algorithms
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    public enum PublicKeyAlgorithm
    {
        // ECDSA w/ SHA-256
        Es256 = -7,

        // EdDSA
        EdDsa = -8,

        // ECDSA w/ SHA-384
        Es384 = -35,

        // ECDSA w/ SHA-512
        Es512 = -36,

        // RSASSA-PSS w/ SHA-256
        Ps256 = -37,

        // RSASSA-PSS w/ SHA-384
        PS384 = -38,

        // RSASSA-PSS w/ SHA-512
        PS512 = -39,

        // RSASSA-PKCS1-v1_5 using SHA-256
        Rs256 = -257,
    }
}
