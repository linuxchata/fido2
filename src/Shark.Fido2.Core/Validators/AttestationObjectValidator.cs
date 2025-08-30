using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

internal class AttestationObjectValidator : IAttestationObjectValidator
{
    private readonly IAttestationStatementValidator _attestationStatementValidator;
    private readonly IAttestationTrustworthinessValidator _attestationTrustworthinessValidator;
    private readonly IAttestationTrustAnchorValidator _attestationTrustAnchorValidator;
    private readonly Fido2Configuration _configuration;

    public AttestationObjectValidator(
        IAttestationStatementValidator attestationStatementValidator,
        IAttestationTrustworthinessValidator attestationTrustworthinessValidator,
        IAttestationTrustAnchorValidator attestationTrustAnchorValidator,
        IOptions<Fido2Configuration> options)
    {
        _attestationStatementValidator = attestationStatementValidator;
        _attestationTrustworthinessValidator = attestationTrustworthinessValidator;
        _attestationTrustAnchorValidator = attestationTrustAnchorValidator;
        _configuration = options.Value;
    }

    public async Task<ValidatorInternalResult> Validate(
        AttestationObjectData? attestationObjectData,
        ClientData clientData,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        if (attestationObjectData == null)
        {
            return ValidatorInternalResult.Invalid("Attestation object cannot be null");
        }

        if (clientData == null)
        {
            return ValidatorInternalResult.Invalid("Client data cannot be null");
        }

        if (creationOptions == null)
        {
            return ValidatorInternalResult.Invalid("Creation options cannot be null");
        }

        var authenticatorData = attestationObjectData.AuthenticatorData;
        if (authenticatorData == null)
        {
            return ValidatorInternalResult.Invalid("Authenticator data cannot be null");
        }

        // 7.1. Registering a New Credential (Steps 13 to 21)

        // Step 13
        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        var rpIdHash = HashProvider.GetSha256Hash(_configuration.RelyingPartyId);
        if (!BytesArrayComparer.CompareAsSpan(rpIdHash, authenticatorData.RpIdHash))
        {
            return ValidatorInternalResult.Invalid("RP ID hash mismatch");
        }

        // Step 14
        // Verify that the User Present bit of the flags in authData is set.
        if (creationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequirement.Required &&
            !authenticatorData.UserPresent)
        {
            return ValidatorInternalResult.Invalid("User Present bit is not set as user verification is required");
        }

        // Step 15
        // If user verification is required for this registration, verify that the User Verified bit of the flags
        // in authData is set.
        if (creationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequirement.Required &&
            !authenticatorData.UserVerified)
        {
            return ValidatorInternalResult.Invalid("User Verified bit is not set as user verification is required");
        }

        // Step 16
        // Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of
        // one of the items in options.pubKeyCredParams.
        var algorithm = authenticatorData.AttestedCredentialData.CredentialPublicKey?.Algorithm;
        if (!Array.Exists(creationOptions.PublicKeyCredentialParams, p => (int)p.Algorithm == algorithm))
        {
            return ValidatorInternalResult.Invalid("Credential public key algorithm mismatch");
        }

        // Step 17
        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        // extension outputs in the extensions in authData are as expected
        // TODO: Implement

        // Step 18
        // Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against
        // the set of supported WebAuthn Attestation Statement Format Identifier values.
        var attestationStatementFormat = attestationObjectData.AttestationStatementFormat;
        if (attestationStatementFormat == null)
        {
            return ValidatorInternalResult.Invalid("Attestation statement format cannot be null");
        }

        if (!AttestationStatementFormatIdentifier.Supported.Contains(attestationStatementFormat!))
        {
            return ValidatorInternalResult.Invalid(
                $"Attestation statement format [{attestationStatementFormat}] is not supported");
        }

        // Step 19
        // Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by
        // using the attestation statement format fmt's verification procedure given attStmt, authData and hash.
        var result = _attestationStatementValidator.Validate(attestationObjectData, clientData);
        if (!result.IsValid || result is not AttestationStatementInternalResult)
        {
            return result;
        }

        // Step 20
        // If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
        // for that attestation type and attestation statement format fmt, from a trusted source or from policy.
        // For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        // using the aaguid in the attestedCredentialData in authData.
        var trustAnchorValidationResult = await _attestationTrustAnchorValidator.Validate(
            attestationObjectData.AuthenticatorData!);
        if (!trustAnchorValidationResult.IsValid)
        {
            return trustAnchorValidationResult;
        }

        // Step 21
        // Assess the attestation trustworthiness using the outputs of the verification procedure in step 19
        var trustworthinessResult = await _attestationTrustworthinessValidator.Validate(
            attestationObjectData.AuthenticatorData!,
            (AttestationStatementInternalResult)result);
        if (!trustworthinessResult.IsValid)
        {
            return trustworthinessResult;
        }

        return ValidatorInternalResult.Valid();
    }
}
