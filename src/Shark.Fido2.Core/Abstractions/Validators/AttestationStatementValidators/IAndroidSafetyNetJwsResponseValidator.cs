using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

public interface IAndroidSafetyNetJwsResponseValidator
{
    bool Validate(JwsResponse jwsResponse, X509Certificate2 certificate);
}
