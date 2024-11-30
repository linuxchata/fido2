﻿using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Helpers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results.Attestation;

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

        public InternalResult<AttestationObjectDataModel> Handle(string attestationObject)
        {
            if (string.IsNullOrWhiteSpace(attestationObject))
            {
                return new InternalResult<AttestationObjectDataModel>("Attestation object cannot be null");
            }

            var attestationObjectData = GetAttestationObjectData(attestationObject);

            var result = _attestationObjectValidator.Validate(attestationObjectData);
            if (!result.IsValid)
            {
                return new InternalResult<AttestationObjectDataModel>(result.Message!);
            }

            return new InternalResult<AttestationObjectDataModel>(attestationObjectData!);
        }

        private AttestationObjectDataModel GetAttestationObjectData(string attestationObject)
        {
            var decodedAttestationObject = CborConverter.Decode(attestationObject);

            var authenticatorDataArray = decodedAttestationObject[AttestationObjectKey.AuthData] as byte[];
            var authenticatorData = _authenticatorDataProvider.Get(authenticatorDataArray);

            var attestationObjectData = new AttestationObjectDataModel
            {
                AttestationStatementFormat = decodedAttestationObject[AttestationObjectKey.Fmt] as string,
                AttestationStatement = decodedAttestationObject[AttestationObjectKey.AttStmt] as object,
                AuthenticatorData = authenticatorData,
            };

            return attestationObjectData;
        }
    }
}
