using System;
using System.Collections.Generic;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators
{
    /// <summary>
    /// 8.2. Packed Attestation Statement Format
    /// </summary>
    internal class PackedAttestationStatementStategy : IAttestationStatementStategy
    {
        public ValidatorInternalResult Validate(
            object? attestationStatement,
            AuthenticatorData authenticatorData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            if (attestationStatement == null)
            {
                throw new ArgumentNullException(nameof(attestationStatement));
            }

            var attestationStatementDict = attestationStatement as Dictionary<string, object>;

            if (attestationStatementDict == null)
            {
                throw new ArgumentNullException(nameof(attestationStatement), "Attestation statement cannot be read");
            }

            if (!attestationStatementDict.TryGetValue("alg", out var algorithm) || !(algorithm is int))
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
            }

            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            if (authenticatorData.AttestedCredentialData.CredentialPublicKey.Algorithm != (int)algorithm)
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
            }

            if (!attestationStatementDict.TryGetValue("sig", out var signature) || !(signature is byte[]))
            {
                return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
            }

            return ValidatorInternalResult.Valid();
        }
    }
}
