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
            AttestationObjectData attestationObjectData,
            ClientData clientData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            var attestationStatement = attestationObjectData.AttestationStatement;
            if (attestationStatement == null)
            {
                throw new ArgumentNullException(nameof(attestationStatement));
            }

            if (!(attestationStatement is Dictionary<string, object> attestationStatementDict))
            {
                throw new ArgumentNullException(nameof(attestationStatement), "Attestation statement cannot be read");
            }

            if (!attestationStatementDict.TryGetValue("alg", out var algorithm) || !(algorithm is int))
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
            }

            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            var attestedCredentialData = attestationObjectData.AuthenticatorData!.AttestedCredentialData;
            if (attestedCredentialData.CredentialPublicKey.Algorithm != (int)algorithm)
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
            }

            if (!attestationStatementDict.TryGetValue("sig", out var signature) || !(signature is byte[]))
            {
                return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
            }

            var a = attestationObjectData.AuthenticatorRawData;
            var c = clientData.ClientDataHash;

            return ValidatorInternalResult.Valid();
        }
    }
}
