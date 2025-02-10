using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal class AlgorithmAttestationStatementValidator : IAlgorithmAttestationStatementValidator
{
    public ValidatorInternalResult Validate(
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey)
    {
        // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        if (!attestationStatementDict.TryGetValue(AttestationStatement.Algorithm, out var algorithm) ||
            algorithm is not int)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
        }

        if (credentialPublicKey.Algorithm != (int)algorithm)
        {
            return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
        }

        return ValidatorInternalResult.Valid();
    }
}
