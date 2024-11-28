using System;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Core.Results;

namespace Shark.Fido2.Core.Validators
{
    internal class ClientDataValidator : IClientDataValidator
    {
        private readonly Fido2Configuration _configuration;

        public ClientDataValidator(IOptions<Fido2Configuration> options)
        {
            _configuration = options.Value;
        }

        public ValidatorInternalResult Validate(ClientDataModel? clientData, string expectedChallenge)
        {
            if (clientData == null)
            {
                return ValidatorInternalResult.Invalid("Client data cannot be null");
            }

            // Type
            if (!string.Equals(clientData.Type, WebauthnType.Create, StringComparison.OrdinalIgnoreCase))
            {
                return ValidatorInternalResult.Invalid(
                    $"Type mismatch. Expected type is {WebauthnType.Create}");
            }

            // Challenge
            var base64StringChallenge = Base64UrlConverter.ToBase64(clientData?.Challenge!);
            if (!Base64Comparer.Compare(expectedChallenge!, base64StringChallenge))
            {
                return ValidatorInternalResult.Invalid("Challenge mismatch");
            }

            // Origin
            if (!Uri.TryCreate(clientData?.Origin, UriKind.Absolute, out var originUri))
            {
                return ValidatorInternalResult.Invalid("Invalid origin");
            }

            var expectedOrigin = _configuration.Origin;

            if (!string.Equals(originUri.Host, expectedOrigin, StringComparison.OrdinalIgnoreCase))
            {
                return ValidatorInternalResult.Invalid("Origin mismatch");
            }

            // Token binding
            if (clientData?.TokenBinding != null)
            {
                throw new NotImplementedException("See #10 of 7.1. Registering a New Credential");
            }

            return ValidatorInternalResult.Valid();
        }
    }
}
