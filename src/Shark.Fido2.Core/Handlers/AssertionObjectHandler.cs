using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers;

internal class AssertionObjectHandler : IAssertionObjectHandler
{
    private readonly IAuthenticatorDataParserService _authenticatorDataParserService;
    private readonly IAssertionObjectValidator _assertionObjectValidator;

    public AssertionObjectHandler(
        IAuthenticatorDataParserService authenticatorDataParserService,
        IAssertionObjectValidator assertionResponseValidator)
    {
        _authenticatorDataParserService = authenticatorDataParserService;
        _assertionObjectValidator = assertionResponseValidator;
    }

    public InternalResult<AuthenticatorData> Handle(
        string authenticatorDataString,
        ClientData clientData,
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

        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);
        var authenticatorData = _authenticatorDataParserService.Parse(authenticatorDataArray);

        var result = _assertionObjectValidator.Validate(authenticatorData, clientData, requestOptions);
        if (!result.IsValid)
        {
            return new InternalResult<AuthenticatorData>(result.Message!);
        }

        return new InternalResult<AuthenticatorData>(authenticatorData!);
    }
}
