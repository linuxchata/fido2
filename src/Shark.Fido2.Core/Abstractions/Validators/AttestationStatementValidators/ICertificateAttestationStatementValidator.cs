using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

public interface ICertificateAttestationStatementValidator
{
    ValidatorInternalResult ValidatePacked(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    ValidatorInternalResult ValidateTpm(
        X509Certificate2 attestationCertificate,
        AttestationObjectData attestationObjectData);

    ValidatorInternalResult ValidateAndroidSafetyNet(X509Certificate2 attestationCertificate);

    ValidatorInternalResult ValidateChainOfTrustWithSystemCa(List<X509Certificate2> certificates);
}
