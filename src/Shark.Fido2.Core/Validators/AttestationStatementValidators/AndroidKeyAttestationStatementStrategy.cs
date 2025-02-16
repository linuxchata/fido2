using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Android Key attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.4.
/// See: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
/// </summary>
internal class AndroidKeyAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ISignatureAttestationStatementValidator _signatureValidator;
    private readonly ICertificateAttestationStatementService _certificateProvider;
    private readonly ICertificateAttestationStatementValidator _certificateValidator;

    public AndroidKeyAttestationStatementStrategy(
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        ICertificateAttestationStatementService certificateAttestationStatementProvider,
        ICertificateAttestationStatementValidator certificateAttestationStatementValidator)
    {
        _signatureValidator = signatureAttestationStatementValidator;
        _certificateProvider = certificateAttestationStatementProvider;
        _certificateValidator = certificateAttestationStatementValidator;
    }

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

        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);
        var attestationCertificate = _certificateProvider.GetAttestationCertificate(certificates);
        var result = _signatureValidator.Validate(
            concatenatedData,
            attestationStatementDict,
            credentialPublicKey,
            attestationCertificate);
        if (!result.IsValid)
        {
            return result;
        }

        // Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
        // attestedCredentialData in authenticatorData.
        // TODO: Implement this check.
        result = _certificateValidator.ValidateAndroidKey(attestationCertificate, attestationObjectData);
        if (!result.IsValid)
        {
            return result;
        }

        // If successful, return implementation-specific values representing attestation type Basic and attestation
        // trust path x5c.
        return new AttestationStatementInternalResult(AttestationTypeEnum.Basic, [.. certificates]);
    }
}
