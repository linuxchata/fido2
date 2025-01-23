using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ICryptographyValidator
{
    bool IsValid(byte[] data, byte[] signature, CredentialPublicKey credentialPublicKey);
}
