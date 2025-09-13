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
/// Implementation of the Packed attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.2.
/// See: https://www.w3.org/TR/webauthn/#sctn-packed-attestation.
/// </summary>
internal class PackedAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly IAttestationCertificateProviderService _attestationCertificateProviderService;
    private readonly IAttestationCertificateValidator _attestationCertificateValidator;
    private readonly ILogger<PackedAttestationStatementStrategy> _logger;

    public PackedAttestationStatementStrategy(
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        IAttestationCertificateProviderService certificateAttestationStatementProvider,
        IAttestationCertificateValidator certificateAttestationStatementValidator,
        ILogger<PackedAttestationStatementStrategy> logger)
    {
        _signatureValidator = signatureAttestationStatementValidator;
        _attestationCertificateProviderService = certificateAttestationStatementProvider;
        _attestationCertificateValidator = certificateAttestationStatementValidator;
        _logger = logger;
    }

    /// <summary>
    /// Validates a Packed attestation statement.
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
            throw new ArgumentException("Packed attestation statement cannot be read", nameof(attestationObjectData));
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        // Validate for both cases when x5c is present and when x5c is not present (Conformance Tools requirement)
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Algorithm, out var algorithm) ||
            algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Packed attestation statement algorithm cannot be read");
        }

        if (credentialPublicKey?.Algorithm != (int)algorithm)
        {
            return ValidatorInternalResult.Invalid(
                $"Packed attestation statement algorithm ({algorithm}) does not match credential public key algorithm ({credentialPublicKey?.Algorithm})");
        }

        _logger.LogDebug("Attestation statement algorithm matches credential public key algorithm");

        if (_attestationCertificateProviderService.AreCertificatesPresent(attestationStatementDict))
        {
            _logger.LogDebug("Attestation certificate is present");

            // If x5c is present
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the attestation public key in attestnCert with the algorithm specified in alg.
            var certificates = _attestationCertificateProviderService.GetCertificates(attestationStatementDict);
            var attestationCertificate = _attestationCertificateProviderService.GetAttestationCertificate(certificates);
            var result = _signatureValidator.Validate(
                concatenatedData,
                attestationStatementDict,
                credentialPublicKey,
                attestationCertificate);
            if (!result.IsValid)
            {
                return result;
            }

            _logger.LogDebug("Signature is verified");

            // Verify that attestnCert meets the requirements in 8.2.1 Packed Attestation Statement Certificate Requirements.
            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the aaguid in authenticatorData.
            result = _attestationCertificateValidator.ValidatePacked(attestationCertificate, attestationObjectData);
            if (!result.IsValid)
            {
                return result;
            }

            _logger.LogDebug("Attestation certificate is valid");

            // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys
            // a Basic or AttCA attestation.
            var attestationType = IsRootCertificate(attestationCertificate) ?
                AttestationType.AttCA : AttestationType.Basic;

            // Verify that trust path does not contain a root certificate
            if (certificates[1..].Exists(IsRootCertificate))
            {
                return ValidatorInternalResult.Invalid("Trust path contains a root certificate");
            }

            _logger.LogDebug("Trust path is valid");
            _logger.LogDebug("Packed attestation statement is valid");

            // If successful, return implementation-specific values representing attestation type Basic, AttCA or
            // uncertainty, and attestation trust path x5c.
            return new AttestationStatementInternalResult(
                AttestationStatementFormatIdentifier.Packed,
                attestationType,
                [.. certificates]);
        }
        else
        {
            _logger.LogDebug("Attestation certificate is not present");

            // If x5c is not present, self attestation is in use.
            // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
            // using the credential public key with alg.
            var result = _signatureValidator.Validate(concatenatedData, attestationStatementDict, credentialPublicKey);
            if (!result.IsValid)
            {
                return result;
            }

            _logger.LogDebug("Signature is verified");
            _logger.LogDebug("Packed attestation statement is valid");

            // If successful, return implementation-specific values representing attestation type Self and an empty
            // attestation trust path.
            return new AttestationStatementInternalResult(
                AttestationStatementFormatIdentifier.Packed,
                AttestationType.Self);
        }
    }

    private static bool IsRootCertificate(X509Certificate2 certificate)
    {
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }
}
