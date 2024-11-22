using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions
{
    public interface IAttestation
    {
        PublicKeyCredentialCreationOptions GetOptions();

        void Complete(PublicKeyCredential publicKeyCredential, string? expectedChallenge);
    }
}
