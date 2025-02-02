using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ICryptographyValidator
{
    bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, CredentialPublicKey credentialPublicKey);

    bool IsValid(byte[] data, byte[] signature, X509Certificate2 attestationCertificate, int algorithm);
}
