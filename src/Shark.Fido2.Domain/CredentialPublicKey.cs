namespace Shark.Fido2.Domain;

/// <summary>
/// The credential's public key.
/// </summary>
public sealed class CredentialPublicKey
{
    /// <summary>
    /// Gets or sets the identification of the key type (kty).
    /// </summary>
    public int KeyType { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic signature algorithm (alg).
    /// </summary>
    public int Algorithm { get; set; }

    /// <summary>
    /// Gets or sets the RSA modulus n.
    /// </summary>
    public byte[]? Modulus { get; set; }

    /// <summary>
    /// Gets or sets the RSA public exponent e.
    /// </summary>
    public byte[]? Exponent { get; set; }

    /// <summary>
    /// Gets or sets the elliptic curves
    /// https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1.
    /// </summary>
    public int? Curve { get; set; }

    /// <summary>
    /// Gets or sets X-coordinate for the elliptic curve point.
    /// </summary>
    public byte[]? XCoordinate { get; set; }

    /// <summary>
    /// Gets or sets Y-coordinate for the elliptic curve point.
    /// </summary>
    public byte[]? YCoordinate { get; set; }

    /// <summary>
    /// Gets or sets the symmetric key.
    /// </summary>
    public byte[]? Key { get; set; }
}
