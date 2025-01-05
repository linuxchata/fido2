using System.Threading.Tasks;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions
{
    public interface IAttestation
    {
        PublicKeyCredentialCreationOptions GetOptions(PublicKeyCredentialCreationOptionsRequest request);

        PublicKeyCredentialRequestOptions RequestOptions(PublicKeyCredentialRequestOptionsRequest request);

        Task<AttestationCompleteResult> Complete(PublicKeyCredential publicKeyCredential, string? expectedChallenge);
    }
}
