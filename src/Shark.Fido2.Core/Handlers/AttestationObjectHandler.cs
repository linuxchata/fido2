using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Results.Attestation;
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

        public InternalResult<AttestationObjectData> Handle(
            string attestationObject,
            ClientData clientData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            if (string.IsNullOrWhiteSpace(attestationObject))
            {
                return new InternalResult<AttestationObjectData>("Attestation object cannot be null");
            }

            if (creationOptions == null)
            {
                return new InternalResult<AttestationObjectData>("Creation options cannot be null");
            }

            var attestationObjectData = GetAttestationObjectData(attestationObject);

            var result = _attestationObjectValidator.Validate(attestationObjectData, clientData, creationOptions);
            if (!result.IsValid)
            {
                return new InternalResult<AttestationObjectData>(result.Message!);
            }

            return new InternalResult<AttestationObjectData>(attestationObjectData!);
        }

        private AttestationObjectData GetAttestationObjectData(string attestationObject)
        {
            var decodedAttestationObject = CborConverter.Decode(attestationObject);

            var authenticatorDataArray = decodedAttestationObject[AttestationObjectKey.AuthData] as byte[];
            var authenticatorData = _authenticatorDataProvider.Get(authenticatorDataArray);

            var attestationObjectData = new AttestationObjectData
            {
                AttestationStatementFormat = decodedAttestationObject[AttestationObjectKey.Fmt] as string,
                AttestationStatement = decodedAttestationObject[AttestationObjectKey.AttStmt],
                AuthenticatorData = authenticatorData,
                AuthenticatorRawData = authenticatorDataArray!,
            };

            return attestationObjectData;
        }
    }
}
