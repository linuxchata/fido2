namespace Shark.Fido2.Core.Enums;

/// <summary>
/// COSE Key Types
/// https://www.iana.org/assignments/cose/cose.xhtml#key-type
/// https://www.rfc-editor.org/rfc/rfc9053.html#initial-kty-caps
/// </summary>
internal enum KeyTypeEnum
{
    /// <summary>
    /// Octet Key Pair
    /// </summary>
    Okp = 1,

    /// <summary>
    /// Elliptic Curve keys
    /// </summary>
    Ec2 = 2,

    /// <summary>
    /// RSA keys
    /// </summary>
    Rsa = 3,

    /// <summary>
    /// Symmetric keys
    /// </summary>
    Symmetric = 4,
}
