using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ICryptographyValidator
{
    bool IsValid(
        byte[] data,
        byte[] signature,
        CredentialPublicKey credentialPublicKey,
        X509Certificate2? attestationCertificate = null);

    bool IsValid(byte[] data, byte[] signature, int algorithm, X509Certificate2 attestationCertificate);
}
