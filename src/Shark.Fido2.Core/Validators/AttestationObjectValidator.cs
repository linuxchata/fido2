using Shark.Fido2.Core.Abstractions.Validators;
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
                AttestationCompleteResult.CreateFailure("Authenticator data cannot be null");
            }

            // Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
            var rpId = "localhost"; // TODO: Take from configuration?
            var rpIdHash = HashProvider.GetSha256Hash(rpId);
            if (BytesArrayComparer.CompareAsSpan(rpIdHash, rpIdHash))
            {
                return AttestationCompleteResult.CreateFailure("SHA-256 hash of the RP ID mismatch");
            }

            // Verify that the User Present bit of the flags in authData is set.
            // TODO: Currently User Present bit is set to false.

            return null;
        }
    }
}
