using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Android Key attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.4.
/// See: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation.
/// </summary>
internal class AndroidKeyAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly IAttestationCertificateProviderService _attestationCertificateProviderService;
    private readonly IAttestationCertificateValidator _attestationCertificateValidator;
    private readonly ICertificatePublicKeyValidator _certificatePublicKeyValidator;

    public AndroidKeyAttestationStatementStrategy(
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        IAttestationCertificateProviderService attestationCertificateProviderService,
        IAttestationCertificateValidator attestationCertificateValidator,
        ICertificatePublicKeyValidator certificatePublicKeyValidator)
    {
        _signatureValidator = signatureAttestationStatementValidator;
        _attestationCertificateProviderService = attestationCertificateProviderService;
        _attestationCertificateValidator = attestationCertificateValidator;
        _certificatePublicKeyValidator = certificatePublicKeyValidator;
    }

    /// <summary>
    /// Validates an Android Key attestation statement.
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
                "Android Key attestation statement cannot be read",
                nameof(attestationObjectData));
        }

        var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;

        // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the public key in the first certificate in x5c with the algorithm specified in alg.
        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        var certificates = _attestationCertificateProviderService.GetCertificates(attestationStatementDict);
        var attestationCertificate = _attestationCertificateProviderService.GetAttestationCertificate(certificates);
        var result = _signatureValidator.Validate(
            concatenatedData,
            attestationStatementDict,
            credentialPublicKey!,
            attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
        // attestedCredentialData in authenticatorData.
        result = _certificatePublicKeyValidator.Validate(attestationCertificate, credentialPublicKey!);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that the attestationChallenge field in the attestation certificate extension data is identical
        // to clientDataHash.
        // Verify using the appropriate authorization list from the attestation certificate extension data.
        result = _attestationCertificateValidator.ValidateAndroidKey(attestationCertificate, clientData);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type Basic and attestation
        // trust path x5c.
        return new AttestationStatementInternalResult(
            AttestationStatementFormatIdentifier.AndroidKey,
            AttestationTypeEnum.Basic,
            [.. certificates]);
    }
}
