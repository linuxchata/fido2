using System;
using System.Text;
using System.Text.Json;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results.Attestation;

namespace Shark.Fido2.Core.Handlers
{
    internal class ClientDataHandler : IClientDataHandler
    {
        private readonly IClientDataValidator _clientDataValidator;

        public ClientDataHandler(IClientDataValidator clientDataValidator)
        {
            _clientDataValidator = clientDataValidator;
        }

        public InternalResult<ClientDataModel> Handle(string clientDataJson, string expectedChallenge)
        {
            if (string.IsNullOrWhiteSpace(clientDataJson))
            {
                return new InternalResult<ClientDataModel>("Client data JSON cannot be null");
            }

            var clientData = GetClientData(clientDataJson);

            var result = _clientDataValidator.Validate(clientData, expectedChallenge);
            if (!result.IsValid)
            {
                return new InternalResult<ClientDataModel>(result.Message!);
            }

            return new InternalResult<ClientDataModel>(clientData!);
        }

        private ClientDataModel? GetClientData(string clientDataJson)
        {
            var clientDataJsonArray = Convert.FromBase64String(clientDataJson);
            var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);
            return JsonSerializer.Deserialize<ClientDataModel>(decodedClientDataJson);
        }
    }
}
