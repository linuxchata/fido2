namespace Shark.Fido2.Domain;

/// <summary>
/// Credential Public Key
/// </summary>
public sealed class CredentialPublicKey
{
    /// <summary>
    /// The identification of the key type (kty)
    /// </summary>
    public int? KeyType { get; set; }

    /// <summary>
    /// The cryptographic signature algorithm (alg)
    /// </summary>
    public int? Algorithm { get; set; }

    /// <summary>
    /// The RSA modulus n
    /// </summary>
    public byte[]? Modulus { get; set; }

    /// <summary>
    /// The RSA public exponent e
    /// </summary>
    public byte[]? Exponent { get; set; }

    /// <summary>
    /// The elliptic curves
    /// https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1
    /// </summary>
    public int? Curve { get; set; }

    /// <summary>
    /// X-coordinate for the elliptic curve point
    /// </summary>
    public byte[]? XCoordinate { get; set; }

    /// <summary>
    /// Y-coordinate for the elliptic curve point
    /// </summary>
    public byte[]? YCoordinate { get; set; }

    /// <summary>
    /// The symmetric key
    /// </summary>
    public byte[]? Key { get; set; }
}
