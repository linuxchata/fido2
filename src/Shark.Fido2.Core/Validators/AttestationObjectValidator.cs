using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators
{
    internal class AttestationObjectValidator : IAttestationObjectValidator
    {
        private readonly Fido2Configuration _configuration;

        public AttestationObjectValidator(IOptions<Fido2Configuration> options)
        {
            _configuration = options.Value;
        }

        public ValidatorInternalResult Validate(AttestationObjectData? attestationObjectData)
        {
            if (attestationObjectData == null)
            {
                return ValidatorInternalResult.Invalid("Attestation Object cannot be null");
            }

            var authenticatorData = attestationObjectData.AuthenticatorData;
            if (authenticatorData == null)
            {
                return ValidatorInternalResult.Invalid("Authenticator Data cannot be null");
            }

            // 7.1. Registering a New Credential (#13 - #10)

            // #13 Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected
            // by the Relying Party.
            var rpIdHash = HashProvider.GetSha256Hash(_configuration.RelyingPartyId);
            if (!BytesArrayComparer.CompareAsSpan(rpIdHash, authenticatorData.RpIdHash))
            {
                return ValidatorInternalResult.Invalid("RP ID mismatch");
            }

            // #14 Verify that the User Present bit of the flags in authData is set.
            if (!authenticatorData.UserPresent)
            {
                return ValidatorInternalResult.Invalid("User Present bit is not set");
            }

            // #15 If user verification is required for this registration, verify that the User Verified
            // bit of the flags in authData is set.
            if (!authenticatorData.UserVerified)
            {
                return ValidatorInternalResult.Invalid("User Verified bit is not set");
            }

            // Verify that the "alg" parameter in the credential public key in authData
            // matches the alg attribute of one of the items in options.pubKeyCredParams.
            // TODO: Fix compare? Should it be taken from configuration?
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Algorithm.HasValue)
            {
                return ValidatorInternalResult.Invalid("Credential public key algorithm is not set");
            }

            // Verify that the values of the client extension outputs in clientExtensionResults
            // and the authenticator extension outputs in the extensions in authData are as expected
            // TODO: Implement

            // Case-sensitive match on fmt against the set of supported WebAuthn
            // Attestation Statement Format Identifier values
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

            return ValidatorInternalResult.Valid();
        }
    }
}
