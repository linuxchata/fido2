using System;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers
{
    internal class AttestationObjectHandler : IAttestationObjectHandler
    {
        private readonly IAuthenticatorDataProvider _authenticatorDataProvider;
        private readonly IAttestationObjectValidator _attestationObjectValidator;

        public AttestationObjectHandler(
            IAuthenticatorDataProvider authenticatorDataProvider,
            IAttestationObjectValidator attestationObjectValidator)
        {
            _authenticatorDataProvider = authenticatorDataProvider;
            _attestationObjectValidator = attestationObjectValidator;
        }

        public AttestationCompleteResult? Handle(string attestationObject)
        {
            if (string.IsNullOrWhiteSpace(attestationObject))
            {
                return AttestationCompleteResult.CreateFailure("Attestation object cannot be null");
            }

            var authenticatorDataArray = GetAuthenticatorData(attestationObject);
            if (authenticatorDataArray == null)
            {
                return AttestationCompleteResult.CreateFailure("Authenticator data cannot be null");
            }

            var hash = HashProvider.GetSha256Hash("localhost");

            var authenticatorData = _authenticatorDataProvider.Get(authenticatorDataArray);

            throw new NotImplementedException();
        }

        private byte[]? GetAuthenticatorData(string attestationObject)
        {
            var decodedAttestationObject = CborConverter.Decode(attestationObject);
            return decodedAttestationObject["authData"] as byte[];
        }
    }
}
