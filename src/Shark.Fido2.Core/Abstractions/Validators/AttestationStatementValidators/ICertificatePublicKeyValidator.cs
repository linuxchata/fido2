using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

public interface ICertificatePublicKeyValidator
{
    ValidatorInternalResult Validate(X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey);
}
