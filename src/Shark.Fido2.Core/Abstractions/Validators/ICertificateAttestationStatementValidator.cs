using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ICertificateAttestationStatementValidator
{
    ValidatorInternalResult Validate(
        Dictionary<string, object> attestationStatementDict,
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);
}
