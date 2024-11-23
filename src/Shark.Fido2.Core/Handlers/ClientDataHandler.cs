using System;
using System.Text;
using System.Text.Json;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Models;
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

        public AttestationCompleteResult? Handle(string clientDataJson, string expectedChallenge)
        {
            if (string.IsNullOrWhiteSpace(clientDataJson))
            {
                return AttestationCompleteResult.CreateFailure("Client data JSON cannot be null");
            }

            var clientData = GetClientData(clientDataJson);

            return _clientDataValidator.Validate(clientData, expectedChallenge);
        }

        private ClientDataModel? GetClientData(string clientDataJson)
        {
            var clientDataJsonArray = Convert.FromBase64String(clientDataJson);
            var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);
            return JsonSerializer.Deserialize<ClientDataModel>(decodedClientDataJson);
        }
    }
}
