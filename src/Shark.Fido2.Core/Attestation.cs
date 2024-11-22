using System;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core
{
    public sealed class Attestation : IAttestation
    {
        private readonly IChallengeGenerator _challengeGenerator;
        private readonly Fido2Configuration _configuration;

        public Attestation(
            IChallengeGenerator challengeGenerator,
            IOptions<Fido2Configuration> options)
        {
            _challengeGenerator = challengeGenerator;
            _configuration = options.Value;
        }

        public PublicKeyCredentialCreationOptions GetOptions()
        {
            var credentialOptions = new PublicKeyCredentialCreationOptions
            {
                Challenge = _challengeGenerator.Get()
            };

            return credentialOptions;
        }

        public void Complete(PublicKeyCredential publicKeyCredential, string? expectedChallenge)
        {
            if (publicKeyCredential == null)
            {
                throw new ArgumentNullException(nameof(publicKeyCredential));
            }

            if (string.IsNullOrWhiteSpace(expectedChallenge))
            {
                throw new ArgumentNullException(nameof(expectedChallenge));
            }

            if (publicKeyCredential.Response == null)
            {
                // Return failed result
                return;
            }

            var clientData = GetClientData(publicKeyCredential.Response.ClientDataJson);
            if (clientData == null)
            {
                // Return failed result
                return;
            }

            // Type
            if (!string.Equals(clientData.Type, WebauthnType.Create, StringComparison.OrdinalIgnoreCase))
            {
                // Return failed result
                return;
            }

            // Challenge
            var base64StringChallenge = Base64UrlConverter.ToBase64(clientData?.Challenge!);
            if (!Base64Comparer.Compare(expectedChallenge!, base64StringChallenge))
            {
                // Return failed result
                return;
            }

            // Origin
            var expectedOrigin = _configuration.Origin;

            if (!Uri.TryCreate(clientData.Origin, UriKind.Absolute, out var originUri))
            {
                // Return failed result
                return;
            }

            if (!string.Equals(originUri.Host, expectedOrigin, StringComparison.OrdinalIgnoreCase))
            {
                // Return failed result
                return;
            }

            var decodedAttestationObject = CborConverter.Decode(publicKeyCredential.Response.AttestationObject);
            var authenticatorData = decodedAttestationObject["authData"] as byte[];
            var hash = HashProvider.GetSha256Hash("localhost");

            // Slice array into peaces
            // 6.1. Authenticator Data
            // https://www.w3.org/TR/webauthn-2/#rpidhash
            var rpIdHash = new byte[32];
            Array.Copy(authenticatorData, rpIdHash, 32);
            var result = BytesArrayComparer.CompareAsSpan(hash, rpIdHash);
        }

        private ClientDataModel? GetClientData(string clientDataJson)
        {
            var clientDataJsonArray = Convert.FromBase64String(clientDataJson);
            var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);
            return JsonSerializer.Deserialize<ClientDataModel>(decodedClientDataJson);
        }
    }
}
