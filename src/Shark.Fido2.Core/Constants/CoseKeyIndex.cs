namespace Shark.Fido2.Core.Constants;

/// <summary>
/// COSE Key Objects
/// https://datatracker.ietf.org/doc/html/rfc8152
/// https://datatracker.ietf.org/doc/html/rfc8230
/// </summary>
internal static class CoseKeyIndex
{
    /// <summary>
    /// The family of keys for this structure
    /// </summary>
    public const int KeyType = 1;

    /// <summary>
    /// The algorithm that is used with the key
    /// </summary>
    public const int Algorithm = 3;

    /// <summary>
    /// The RSA modulus n
    /// </summary>
    public const int Modulus = -1;

    /// <summary>
    /// The RSA public exponent e
    /// </summary>
    public const int Exponent = -2;

    /// <summary>
    /// The identifier of the curve to be used with the key
    /// </summary>
    public const int Curve = -1;

    /// <summary>
    /// The x-coordinate for the elliptic curve point
    /// </summary>
    public const int XCoordinate = -2;

    /// <summary>
    /// Either the sign bit or the value of the y-coordinate for the elliptic curve point
    /// </summary>
    public const int YCoordinate = -3;

    /// <summary>
    /// The symmetric key
    /// </summary>
    public const int SymmetricKey = -1;
}
