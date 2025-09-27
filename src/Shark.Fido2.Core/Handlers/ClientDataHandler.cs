using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers;

internal class ClientDataHandler : IClientDataHandler
{
    private readonly IClientDataValidator _clientDataValidator;
    private readonly ILogger<ClientDataHandler> _logger;

    public ClientDataHandler(IClientDataValidator clientDataValidator, ILogger<ClientDataHandler> logger)
    {
        _clientDataValidator = clientDataValidator;
        _logger = logger;
    }

    public InternalResult<ClientData> HandleAttestation(string clientDataJson, string expectedChallenge)
    {
        var validationResult = ValidateClientDataJson(clientDataJson);
        if (validationResult != null)
        {
            return validationResult;
        }

        var clientData = GetAttestationClientData(clientDataJson);

        var result = _clientDataValidator.ValidateForAttestation(clientData, expectedChallenge);
        if (!result.IsValid)
        {
            return new InternalResult<ClientData>(result.Message!);
        }

        _logger.LogDebug("Client data for attestation is valid");

        return new InternalResult<ClientData>(clientData!);
    }

    public InternalResult<ClientData> HandleAssertion(string clientDataJson, string expectedChallenge)
    {
        var validationResult = ValidateClientDataJson(clientDataJson);
        if (validationResult != null)
        {
            return validationResult;
        }

        var clientData = GetAssertionClientData(clientDataJson);

        var result = _clientDataValidator.ValidateForAssertion(clientData, expectedChallenge);
        if (!result.IsValid)
        {
            return new InternalResult<ClientData>(result.Message!);
        }

        _logger.LogDebug("Client data for assertion is valid");

        return new InternalResult<ClientData>(clientData!);
    }

    private InternalResult<ClientData> ValidateClientDataJson(string clientDataJson)
    {
        if (string.IsNullOrWhiteSpace(clientDataJson))
        {
            return new InternalResult<ClientData>("Client data JSON cannot be null");
        }

        if (!clientDataJson.IsBase64Url())
        {
            return new InternalResult<ClientData>("Client data JSON is not base64url encoded");
        }

        return null!;
    }

    private ClientData GetAttestationClientData(string clientDataJson)
    {
        // 7.1. Registering a New Credential (Steps 5 to 6 and 10)

        // Step 5
        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        // Step 6
        // Let C, the client data claimed as collected during the credential creation,
        // be the result of running an implementation-specific JSON parser on JSONtext.
        // Step 11
        // Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        var clientData = GetClientData(clientDataJson);

        _logger.LogDebug("Client data for attestation is parsed");

        return clientData;
    }

    private ClientData GetAssertionClientData(string clientDataJson)
    {
        // 7.2. Verifying an Authentication Assertion (Steps 9, 10 and 19)

        // Step 9
        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // Step 10
        // Let C, the client data claimed as used for the signature, be the result of running an
        // implementation-specific JSON parser on JSONtext.
        // Step 19
        // Let hash be the result of computing a hash over the cData using SHA-256.
        var clientData = GetClientData(clientDataJson);

        _logger.LogDebug("Client data for assertion is parsed");

        return clientData;
    }

    private ClientData GetClientData(string clientDataJson)
    {
        var clientDataJsonArray = clientDataJson.FromBase64Url();
        var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);

        var clientData = JsonSerializer.Deserialize<ClientData>(decodedClientDataJson) ??
            throw new ArgumentException("Client data cannot be read", nameof(clientDataJson));

        clientData.ClientDataHash = HashProvider.GetSha256Hash(clientDataJsonArray);

        return clientData;
    }
}
