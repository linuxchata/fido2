using System;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators
{
    internal class ClientDataValidator : IClientDataValidator
    {
        private readonly Fido2Configuration _configuration;

        public ClientDataValidator(IOptions<Fido2Configuration> options)
        {
            _configuration = options.Value;
        }

        public AttestationCompleteResult? Validate(ClientDataModel? clientData, string expectedChallenge)
        {
            if (clientData == null)
            {
                return AttestationCompleteResult.CreateFailure("Client data cannot be null");
            }

            // Type
            if (!string.Equals(clientData.Type, WebauthnType.Create, StringComparison.OrdinalIgnoreCase))
            {
                return AttestationCompleteResult.CreateFailure($"Type mismatch. Expected type is {WebauthnType.Create}");
            }

            // Challenge
            var base64StringChallenge = Base64UrlConverter.ToBase64(clientData?.Challenge!);
            if (!Base64Comparer.Compare(expectedChallenge!, base64StringChallenge))
            {
                return AttestationCompleteResult.CreateFailure("Challenge mismatch");
            }

            // Origin
            if (!Uri.TryCreate(clientData?.Origin, UriKind.Absolute, out var originUri))
            {
                return AttestationCompleteResult.CreateFailure("Invalid origin");
            }

            var expectedOrigin = _configuration.Origin;

            if (!string.Equals(originUri.Host, expectedOrigin, StringComparison.OrdinalIgnoreCase))
            {
                return AttestationCompleteResult.CreateFailure("Origin mismatch");
            }

            // Token binding
            if (clientData?.TokenBinding != null)
            {
                throw new NotImplementedException("See #10 of 7.1. Registering a New Credential");
            }

            return null;
        }
    }
}
