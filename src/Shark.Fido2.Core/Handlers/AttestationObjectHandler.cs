using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Converters;
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

            var authenticatorData = _authenticatorDataProvider.Get(authenticatorDataArray);

            _attestationObjectValidator.Validate(authenticatorData);

            return null;
        }

        private byte[]? GetAuthenticatorData(string attestationObject)
        {
            var decodedAttestationObject = CborConverter.Decode(attestationObject);

            var attestationStatementFormat = decodedAttestationObject["fmt"] as string;
            var attestationStatement = decodedAttestationObject["attStmt"] as object;
            var authenticatorData = decodedAttestationObject["authData"] as byte[];

            return authenticatorData;
        }
    }
}
