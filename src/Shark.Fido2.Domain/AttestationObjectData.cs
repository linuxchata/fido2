namespace Shark.Fido2.Domain;

/// <summary>
/// Attestation Object Data
/// https://www.w3.org/TR/webauthn-2/#attestation-object.
/// </summary>
public sealed class AttestationObjectData
{
    /// <summary>
    /// Gets an attestation statement format (fmt).
    /// </summary>
    public string? AttestationStatementFormat { get; init; }

    /// <summary>
    /// Gets an attestation statement (attStmt).
    /// </summary>
    public object? AttestationStatement { get; init; }

    /// <summary>
    /// Gets a byte array containing authenticator data (attStmt).
    /// </summary>
    public AuthenticatorData? AuthenticatorData { get; init; }

    /// <summary>
    /// Gets an authenticator raw data.
    /// </summary>
    public byte[]? AuthenticatorRawData { get; init; }
}
