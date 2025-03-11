using Microsoft.Extensions.Options;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators;

internal class AssertionResponseValidator : IAssertionObjectValidator
{
    private readonly ISignatureAttestationStatementValidator _signatureAttestationStatementValidator;
    private readonly Fido2Configuration _configuration;

    public AssertionResponseValidator(
        ISignatureAttestationStatementValidator signatureAttestationStatementValidator,
        IOptions<Fido2Configuration> options)
    {
        _signatureAttestationStatementValidator = signatureAttestationStatementValidator;
        _configuration = options.Value;
    }

    public ValidatorInternalResult Validate(
        byte[] authenticatorRawData,
        AuthenticatorData? authenticatorData,
        string signature,
        ClientData clientData,
        CredentialPublicKey credentialPublicKey,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        if (authenticatorData == null)
        {
            return ValidatorInternalResult.Invalid("Authenticator Data cannot be null");
        }

        if (requestOptions == null)
        {
            return ValidatorInternalResult.Invalid("Request options cannot be null");
        }

        // 7.2. Verifying an Authentication Assertion

        // Step 15
        // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        var rpIdHash = HashProvider.GetSha256Hash(_configuration.RelyingPartyId);
        if (!BytesArrayComparer.CompareAsSpan(rpIdHash, authenticatorData.RpIdHash))
        {
            return ValidatorInternalResult.Invalid("RP ID hash mismatch");
        }

        // Step 16
        // Verify that the User Present bit of the flags in authData is set.
        if (!authenticatorData.UserPresent)
        {
            return ValidatorInternalResult.Invalid("User Present bit is not set");
        }

        // Step 17
        // If user verification is required for this assertion, verify that the User Verified bit of the flags
        // in authData is set.
        if (requestOptions.UserVerification == UserVerificationRequirement.Required &&
            !authenticatorData.UserVerified)
        {
            return ValidatorInternalResult.Invalid("User Verified bit is not set as user verification is required");
        }

        // Step 18
        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        // extension outputs in the extensions in authData are as expected, considering the client extension input
        // values that were given in options.extensions and any specific policy of the Relying Party regarding
        // unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general
        // case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        // TODO: Implement

        // Step 20
        // Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
        // and hash.
        var signatureRawData = signature.FromBase64Url();
        var concatenatedData = BytesArrayHelper.Concatenate(authenticatorRawData, clientData.ClientDataHash);
        var result = _signatureAttestationStatementValidator.Validate(concatenatedData, signatureRawData, credentialPublicKey);
        if (!result.IsValid)
        {
            return result;
        }

        return ValidatorInternalResult.Valid();
    }
}
