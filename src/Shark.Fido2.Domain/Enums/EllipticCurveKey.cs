namespace Shark.Fido2.Domain.Enums;

/// <summary>
/// See: https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.
/// </summary>
public enum EllipticCurveKey
{
    /// <summary>
    /// Ed25519 for use w/ EdDSA only
    /// </summary>
    Ed25519 = 6,
}
