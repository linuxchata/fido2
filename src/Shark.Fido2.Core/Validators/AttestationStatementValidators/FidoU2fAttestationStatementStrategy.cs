using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the FIDO U2F attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.6.
/// See: https://www.w3.org/TR/webauthn/#sctn-fido-u2f-attestation.
/// </summary>
internal class FidoU2FAttestationStatementStrategy : IAttestationStatementStrategy
{
    private const int CoordinateSize = 32;

    private readonly IAttestationCertificateProviderService _attestationCertificateProviderService;
    private readonly IAttestationCertificateValidator _attestationCertificateValidator;
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly ILogger<FidoU2FAttestationStatementStrategy> _logger;

    public FidoU2FAttestationStatementStrategy(
        IAttestationCertificateProviderService attestationCertificateProviderService,
        IAttestationCertificateValidator attestationCertificateValidator,
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ILogger<FidoU2FAttestationStatementStrategy> logger)
    {
        _attestationCertificateProviderService = attestationCertificateProviderService;
        _attestationCertificateValidator = attestationCertificateValidator;
        _signatureValidator = signatureAttestationStatementValidator;
        _logger = logger;
    }

    /// <summary>
    /// Validates a FIDO U2F attestation statement.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate.</param>
    /// <param name="clientData">The client data associated with the attestation.</param>
    /// <returns>A ValidatorInternalResult indicating whether the attestation statement is valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown when attestationObjectData or clientData is null.</exception>
    /// <exception cref="ArgumentException">Thrown when attestation statement cannot be read.</exception>
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
        var certificates = _attestationCertificateProviderService.GetCertificates(attestationStatementDict);
        if (certificates.Count != 1)
        {
            return ValidatorInternalResult.Invalid("FIDO U2F attestation statement must have exactly one certificate");
        }

        var attestationCertificate = _attestationCertificateProviderService.GetAttestationCertificate(certificates);
        var result = _attestationCertificateValidator.ValidateFidoU2F(attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        _logger.LogDebug("Attestation certificate is valid");

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        // Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and
        // confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and
        // return an appropriate error.
        if (credentialPublicKey?.XCoordinate?.Length != CoordinateSize)
        {
            return ValidatorInternalResult.Invalid(
                "FIDO U2F attestation statement credential public key X coordinate is missing or has a wrong size");
        }

        _logger.LogDebug("Credential public key X coordinate is valid");

        // Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and
        // confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and
        // return an appropriate error.
        if (credentialPublicKey.YCoordinate?.Length != CoordinateSize)
        {
            return ValidatorInternalResult.Invalid(
                "FIDO U2F attestation statement credential public key Y coordinate is missing or has a wrong size");
        }

        _logger.LogDebug("Credential public key Y coordinate is valid");

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

        _logger.LogDebug("Signature is verified");

        // (Conformance Tools requirement)
        if (attestationObjectData.AuthenticatorData.AttestedCredentialData.AaGuid != Guid.Empty)
        {
            return ValidatorInternalResult.Invalid("FIDO U2F attestation statement has not empty AAGUID");
        }

        _logger.LogDebug("AAGUID is valid");
        _logger.LogDebug("FIDO U2F attestation statement is valid");

        // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a
        // Basic or AttCA attestation.
        var attestationType = IsRootCertificate(attestationCertificate) ?
            AttestationType.Basic : AttestationType.AttCA;

        // If successful, return implementation-specific values representing attestation type Basic, AttCA or
        // uncertainty, and attestation trust path x5c.
        return new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.FidoU2F,
            attestationType,
            [.. certificates]);
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

    private static bool IsRootCertificate(X509Certificate2 certificate)
    {
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }
}
