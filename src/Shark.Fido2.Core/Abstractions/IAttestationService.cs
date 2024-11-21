using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions
{
    public interface IAttestationService
    {
        PublicKeyCredentialCreationOptions GetOptions();

        void Complete(PublicKeyCredential publicKeyCredential, string? expectedChallenge);
    }
}
