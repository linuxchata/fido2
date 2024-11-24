using System;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core
{
    public sealed class Attestation : IAttestation
    {
        private readonly IClientDataHandler _clientDataHandler;
        private readonly IAttestationObjectHandler _attestationObjectHandler;
        private readonly IChallengeGenerator _challengeGenerator;
        private readonly Fido2Configuration _configuration;

        public Attestation(
            IClientDataHandler clientDataHandler,
            IAttestationObjectHandler attestationObjectHandler,
            IChallengeGenerator challengeGenerator,
            IOptions<Fido2Configuration> options)
        {
            _clientDataHandler = clientDataHandler;
            _attestationObjectHandler = attestationObjectHandler;
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

        public AttestationCompleteResult Complete(PublicKeyCredential publicKeyCredential, string? expectedChallenge)
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
                return AttestationCompleteResult.CreateFailure("Response cannot be null");
            }

            var clientDataHandlerResult = _clientDataHandler.Handle(
                publicKeyCredential.Response.ClientDataJson, expectedChallenge);
            if (clientDataHandlerResult != null)
            {
                return clientDataHandlerResult;
            }

            _attestationObjectHandler.Handle(publicKeyCredential.Response.AttestationObject);

            var decodedAttestationObject = CborConverter.Decode(publicKeyCredential.Response.AttestationObject);

            var authenticatorData = decodedAttestationObject["authData"] as byte[];
            var temp = Convert.ToBase64String(authenticatorData);
            var hash = HashProvider.GetSha256Hash("localhost");

            // Slice array into peaces
            // 6.1. Authenticator Data
            // https://www.w3.org/TR/webauthn-2/#rpidhash
            var rpIdHash = new byte[32];
            Array.Copy(authenticatorData, rpIdHash, 32);
            var result = BytesArrayComparer.CompareAsSpan(hash, rpIdHash);

            return AttestationCompleteResult.Create();
        }
    }
}
