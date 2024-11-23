using System;
using Shark.Fido2.Core.Abstractions.Handlers;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Handlers
{
    internal class AttestationObjectHandler : IAttestationObjectHandler
    {
        private readonly IAttestationObjectValidator _attestationObjectValidator;

        public AttestationObjectHandler(IAttestationObjectValidator attestationObjectValidator)
        {
            _attestationObjectValidator = attestationObjectValidator;
        }

        public AttestationCompleteResult? Handle(string attestationObject)
        {
            if (string.IsNullOrWhiteSpace(attestationObject))
            {
                return AttestationCompleteResult.CreateFailure("Attestation object cannot be null");
            }

            throw new NotImplementedException();
        }
    }
}
