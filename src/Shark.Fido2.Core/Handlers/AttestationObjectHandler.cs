﻿using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Handlers;

internal class AttestationObjectHandler : IAttestationObjectHandler
{
    private readonly IAuthenticatorDataParserService _authenticatorDataParserService;
    private readonly IAttestationObjectValidator _attestationObjectValidator;

    public AttestationObjectHandler(
        IAuthenticatorDataParserService authenticatorDataParserService,
        IAttestationObjectValidator attestationObjectValidator)
    {
        _authenticatorDataParserService = authenticatorDataParserService;
        _attestationObjectValidator = attestationObjectValidator;
    }

    public async Task<InternalResult<AttestationObjectData>> Handle(
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

        var result = await _attestationObjectValidator.Validate(attestationObjectData, clientData, creationOptions);
        if (!result.IsValid)
        {
            return new InternalResult<AttestationObjectData>(result.Message!);
        }

        return new InternalResult<AttestationObjectData>(attestationObjectData!);
    }

    private AttestationObjectData GetAttestationObjectData(string attestationObject)
    {
        // Step 12
        // Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure
        // to obtain the attestation statement format fmt, the authenticator data authData, and the attestation
        // statement attStmt.
        var decodedAttestationObject = CborConverter.Decode(attestationObject);

        var authenticatorDataArray = decodedAttestationObject[AttestationObjectKey.AuthData] as byte[];
        var authenticatorData = _authenticatorDataParserService.Parse(authenticatorDataArray);

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
