using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the FIDO U2F attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.6.
/// See: https://www.w3.org/TR/webauthn/#sctn-fido-u2f-attestation
/// </summary>
internal class FidoU2fAttestationStatementStrategy : IAttestationStatementStrategy
{
    private const int CoordinateSize = 32;

    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateAttestationStatementValidator;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;

    public FidoU2fAttestationStatementStrategy(
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator)
    {
        _certificateProvider = certificateAttestationStatementProvider;
        _certificateAttestationStatementValidator = certificateAttestationStatementValidator;
        _signatureValidator = signatureAttestationStatementValidator;
    }

    /// <summary>
    /// Validates a FIDO U2F attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate</param>
    /// <param name="clientData">The client data associated with the attestation</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid</returns>
    /// <exception cref="ArgumentNullException">Thrown when attestationObjectData or clientData is null</exception>
    /// <exception cref="ArgumentException">Thrown when attestation statement cannot be read</exception>
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException(
                "FIDO U2F attestation statement cannot be read",
                nameof(attestationObjectData));
        }

        // Check that x5c has exactly one element and let attCert be that element. Let certificate public key be
        // the public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public key
        // over the P-256 curve, terminate this algorithm and return an appropriate error.
        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
        if (certificates.Count != 1)
        {
            return ValidatorInternalResult.Invalid("FIDO U2F attestation statement must have exactly one certificate");
        }

        var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);
        var result = _certificateAttestationStatementValidator.ValidateFidoU2f(attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        // Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and
        // confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and
        // return an appropriate error.
        if (credentialPublicKey.XCoordinate?.Length != CoordinateSize)
        {
            return ValidatorInternalResult.Invalid(
                "FIDO U2F attestation statement credential public key X coordinate is missing or has a wrong size");
        }

        // Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and
        // confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and
        // return an appropriate error.
        if (credentialPublicKey.YCoordinate?.Length != CoordinateSize)
        {
            return ValidatorInternalResult.Invalid(
                "FIDO U2F attestation statement credential public key Y coordinate is missing or has a wrong size");
        }

        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        var publicKeyU2f = GetPublicKeyU2f(credentialPublicKey);

        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
        var verificationData = GetVerificationData(attestationObjectData, clientData, publicKeyU2f);

        // Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with
        // SHA-256 as the hash function used in step two.
        result = _signatureValidator.ValidateFido2U2f(verificationData, attestationStatementDict, credentialPublicKey, attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a
        // Basic or AttCA attestation.
        var attestationType = (attestationCertificate.Subject == attestationCertificate.Issuer) ?
            AttestationTypeEnum.Basic : AttestationTypeEnum.AttCA;

        // If successful, return implementation-specific values representing attestation type Basic, AttCA or
        // uncertainty, and attestation trust path x5c.
        return new AttestationStatementInternalResult(attestationType, [.. certificates]);
    }

    private static byte[] GetPublicKeyU2f(CredentialPublicKey credentialPublicKey)
    {
        // 0x04 || x || y
        var coordiantes = BytesArrayHelper.Concatenate(credentialPublicKey.XCoordinate, credentialPublicKey.YCoordinate);
        return BytesArrayHelper.Concatenate([0x04], coordiantes);
    }

    private static byte[] GetVerificationData(
        AttestationObjectData attestationObjectData,
        ClientData clientData,
        byte[] publicKeyU2f)
    {
        var rpIdHash = attestationObjectData.AuthenticatorData!.RpIdHash;
        var credentialId = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialId;

        // 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
        var andRpIdHash = BytesArrayHelper.Concatenate([0x00], rpIdHash);
        var andClientDataHash = BytesArrayHelper.Concatenate(andRpIdHash, clientData.ClientDataHash);
        var andCredentialId = BytesArrayHelper.Concatenate(andClientDataHash, credentialId);
        return BytesArrayHelper.Concatenate(andCredentialId, publicKeyU2f);
    }
}
