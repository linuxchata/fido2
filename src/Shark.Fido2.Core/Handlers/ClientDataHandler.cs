using System;
using System.Text;
using System.Text.Json;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers
{
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

        private ClientData? GetClientData(string clientDataJson)
        {
            var clientDataJsonArray = Convert.FromBase64String(clientDataJson);
            var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);
            return JsonSerializer.Deserialize<ClientData>(decodedClientDataJson);
        }
    }
}
