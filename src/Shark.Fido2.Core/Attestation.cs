﻿using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core
{
    public sealed class Attestation : IAttestation
    {
        private readonly IClientDataHandler _clientDataHandler;
        private readonly IAttestationObjectHandler _attestationObjectHandler;
        private readonly IChallengeGenerator _challengeGenerator;
        private readonly ICredentialRepository _credentialRepository;
        private readonly Fido2Configuration _configuration;

        public Attestation(
            IClientDataHandler clientDataHandler,
            IAttestationObjectHandler attestationObjectHandler,
            IChallengeGenerator challengeGenerator,
            ICredentialRepository credentialRepository,
            IOptions<Fido2Configuration> options)
        {
            _clientDataHandler = clientDataHandler;
            _attestationObjectHandler = attestationObjectHandler;
            _challengeGenerator = challengeGenerator;
            _credentialRepository = credentialRepository;
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

        public async Task<AttestationCompleteResult> Complete(
            PublicKeyCredential publicKeyCredential,
            string? expectedChallenge)
        {
            if (publicKeyCredential == null)
            {
                throw new ArgumentNullException(nameof(publicKeyCredential));
            }

            if (string.IsNullOrWhiteSpace(expectedChallenge))
            {
                throw new ArgumentNullException(nameof(expectedChallenge));
            }

            var response = publicKeyCredential.Response;
            if (response == null)
            {
                return AttestationCompleteResult.CreateFailure("Response cannot be null");
            }

            var clientDataHandlerResult = _clientDataHandler.Handle(response.ClientDataJson, expectedChallenge);
            if (clientDataHandlerResult.HasError)
            {
                return AttestationCompleteResult.CreateFailure(clientDataHandlerResult.Message!);
            }

            var attestationObjectHandlerResult = _attestationObjectHandler.Handle(response.AttestationObject);
            if (attestationObjectHandlerResult.HasError)
            {
                return AttestationCompleteResult.CreateFailure(attestationObjectHandlerResult.Message!);
            }

            var credentialId = attestationObjectHandlerResult.Value?.AuthenticatorData?.AttestedCredentialData.CredentialId;
            var credential = await _credentialRepository.Get(credentialId);
            if (credential != null)
            {
                return AttestationCompleteResult.CreateFailure("Credential has already been registered");
            }

            credential = new Credential { CredentialId = credentialId! };
            await _credentialRepository.Add(credential);

            return AttestationCompleteResult.Create();
        }
    }
}
