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
            string attestationStatementFormat,
            object? attestationStatement,
            AuthenticatorData authenticatorData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            if (string.IsNullOrWhiteSpace(attestationStatementFormat))
            {
                throw new ArgumentNullException(nameof(attestationStatementFormat));
            }

            var strategyMap = new Dictionary<string, IAttestationStatementStategy>
            {
                { AttestationStatementFormatIdentifier.Packed, new PackedAttestationStatementStategy() },
            };

            var strategy = strategyMap.ContainsKey(attestationStatementFormat) ?
                strategyMap[attestationStatementFormat] :
                throw new ArgumentException($"{attestationStatementFormat} is not supported");

            strategy.Validate(attestationStatementFormat, authenticatorData, creationOptions);
        }
    }
}
