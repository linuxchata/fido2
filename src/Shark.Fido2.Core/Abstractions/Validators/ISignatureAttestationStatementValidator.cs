using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ISignatureAttestationStatementValidator
{
    ValidatorInternalResult Validate(
        Dictionary<string, object> attestationStatementDict,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2 attestationCertificate,
        byte[] authenticatorRawData,
        byte[] clientDataHash);
}
