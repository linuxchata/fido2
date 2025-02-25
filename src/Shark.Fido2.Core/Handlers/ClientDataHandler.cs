using System.Text;
using System.Text.Json;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers;

internal class ClientDataHandler : IClientDataHandler
{
    private readonly IClientDataValidator _clientDataValidator;

    public ClientDataHandler(IClientDataValidator clientDataValidator)
    {
        _clientDataValidator = clientDataValidator;
    }

    public InternalResult<ClientData> Handle(string clientDataJson, string expectedChallenge)
    {
        if (string.IsNullOrWhiteSpace(clientDataJson))
        {
            return new InternalResult<ClientData>("Client data JSON cannot be null");
        }

        var clientData = GetClientData(clientDataJson);

        var result = _clientDataValidator.Validate(clientData, expectedChallenge);
        if (!result.IsValid)
        {
            return new InternalResult<ClientData>(result.Message!);
        }

        return new InternalResult<ClientData>(clientData!);
    }

    private ClientData GetClientData(string clientDataJson)
    {
        // 7.1. Registering a New Credential (Steps 5 to 6 and 10)

        // Step 5
        // Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        var clientDataJsonArray = Convert.FromBase64String(clientDataJson);
        var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);

        // Step 6
        // Let C, the client data claimed as collected during the credential creation,
        // be the result of running an implementation-specific JSON parser on JSONtext.
        var clientData = JsonSerializer.Deserialize<ClientData>(decodedClientDataJson);

        if (clientData == null)
        {
            throw new ArgumentException("Client data cannot be read", nameof(clientData));
        }

        // Step 11
        // Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        clientData.ClientDataHash = HashProvider.GetSha256Hash(clientDataJsonArray);

        return clientData;
    }
}
