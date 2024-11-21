using System;
using System.Text;
using System.Text.Json;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core
{
    public sealed class AttestationService : IAttestationService
    {
        private readonly IChallengeGenerator _challengeGenerator;

        public AttestationService(IChallengeGenerator challengeGenerator)
        {
            _challengeGenerator = challengeGenerator;
        }

        public PublicKeyCredentialCreationOptions GetOptions()
        {
            var credentialOptions = new PublicKeyCredentialCreationOptions
            {
                Challenge = _challengeGenerator.Get()
            };

            return credentialOptions;
        }

        public void Complete(PublicKeyCredential publicKeyCredential, string expectedChallenge)
        {
            if (publicKeyCredential == null)
            {
                throw new ArgumentNullException(nameof(publicKeyCredential));
            }

            var clientDataJsonArray = Convert.FromBase64String(publicKeyCredential.Response.ClientDataJson);
            var decodedClientDataJson = Encoding.UTF8.GetString(clientDataJsonArray);

            var clientData = JsonSerializer.Deserialize<ClientDataModel>(decodedClientDataJson);

            var base64StringChallenge = Base64UrlConverter.ToBase64(clientData?.Challenge!);

            if (!Base64Comparer.Compare(expectedChallenge!, base64StringChallenge))
            {
                // Return failed result
            }
        }
    }
}
