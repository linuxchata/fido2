using Microsoft.Extensions.Logging;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Handlers;

internal class AssertionObjectHandler : IAssertionObjectHandler
{
    private readonly IAuthenticatorDataParserService _authenticatorDataParserService;
    private readonly IAssertionObjectValidator _assertionObjectValidator;
    private readonly ILogger<AssertionObjectHandler> _logger;

    public AssertionObjectHandler(
        IAuthenticatorDataParserService authenticatorDataParserService,
        IAssertionObjectValidator assertionResponseValidator,
        ILogger<AssertionObjectHandler> logger)
    {
        _authenticatorDataParserService = authenticatorDataParserService;
        _assertionObjectValidator = assertionResponseValidator;
        _logger = logger;
    }

    public InternalResult<AuthenticatorData> Handle(
        string authenticatorDataString,
        string signature,
        ClientData clientData,
        CredentialPublicKey credentialPublicKey,
        AuthenticationExtensionsClientOutputs extensionsClientOutputs,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        if (string.IsNullOrWhiteSpace(authenticatorDataString))
        {
            return new InternalResult<AuthenticatorData>("Attestation Data cannot be null");
        }

        if (requestOptions == null)
        {
            return new InternalResult<AuthenticatorData>("Request options cannot be null");
        }

        var authenticatorRawData = authenticatorDataString.FromBase64Url();
        var authenticatorData = _authenticatorDataParserService.Parse(authenticatorRawData);

        _logger.LogDebug("Assertion authenticator data is parsed");

        var result = _assertionObjectValidator.Validate(
            authenticatorData,
            authenticatorRawData,
            clientData.ClientDataHash,
            signature,
            credentialPublicKey,
            extensionsClientOutputs,
            requestOptions);
        if (!result.IsValid)
        {
            return new InternalResult<AuthenticatorData>(result.Message!);
        }

        _logger.LogDebug("Assertion authenticator data is valid");

        return new InternalResult<AuthenticatorData>(authenticatorData!);
    }
}
