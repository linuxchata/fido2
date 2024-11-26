﻿using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators
{
    internal class AttestationObjectValidator : IAttestationObjectValidator
    {
        public AttestationCompleteResult? Validate(AuthenticatorDataModel? authenticatorData)
        {
            if (authenticatorData == null)
            {
                AttestationCompleteResult.CreateFailure("Authenticator Data cannot be null");
            }

            // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
            var rpId = "localhost"; // TODO: Take from configuration?
            var rpIdHash = HashProvider.GetSha256Hash(rpId);
            if (!BytesArrayComparer.CompareAsSpan(rpIdHash, authenticatorData!.RpIdHash))
            {
                return AttestationCompleteResult.CreateFailure("SHA-256 hash of the RP ID mismatch");
            }

            // Verify that the User Present bit of the flags in authData is set.
            if (!authenticatorData.UserPresent)
            {
                return AttestationCompleteResult.CreateFailure("User Present bit is not set");
            }

            // If user verification is required for this registration, verify
            // that the User Verified bit of the flags in authData is set.
            if (!authenticatorData.UserVerified)
            {
                return AttestationCompleteResult.CreateFailure("User Verified bit is not set");
            }

            // Verify that the "alg" parameter in the credential public key in authData
            // matches the alg attribute of one of the items in options.pubKeyCredParams.
            // TODO: Fix compare? Should it be taken from configuration?
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Algorithm.HasValue)
            {
                return AttestationCompleteResult.CreateFailure("Credential public key algorithm is not set");
            }

            return null;
        }
    }
}
