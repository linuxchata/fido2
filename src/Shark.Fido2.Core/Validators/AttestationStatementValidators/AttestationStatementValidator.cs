using System;
using System.Collections.Generic;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators
{
    internal class AttestationStatementValidator : IAttestationStatementValidator
    {
        public void Validate(
            AttestationObjectData attestationObjectData,
            AuthenticatorData authenticatorData,
            ClientData clientData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            if (attestationObjectData == null)
            {
                throw new ArgumentNullException(nameof(attestationObjectData));
            }

            var attestationStatementFormat = attestationObjectData.AttestationStatementFormat;

            if (string.IsNullOrEmpty(attestationStatementFormat))
            {
                throw new ArgumentNullException(nameof(attestationStatementFormat));
            }

            var strategyMap = new Dictionary<string, IAttestationStatementStategy>
            {
                { AttestationStatementFormatIdentifier.Packed, new PackedAttestationStatementStategy() },
                { AttestationStatementFormatIdentifier.None, new NoneAttestationStatementStategy() },
            };

            var strategy = strategyMap.ContainsKey(attestationStatementFormat) ?
                strategyMap[attestationStatementFormat] :
                throw new ArgumentException($"{attestationStatementFormat} is not supported");

            strategy.Validate(attestationObjectData, clientData, creationOptions);
        }
    }
}
