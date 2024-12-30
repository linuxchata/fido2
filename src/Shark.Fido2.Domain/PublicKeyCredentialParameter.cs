using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain
{
    public class PublicKeyCredentialParameter
    {
        public string Type { get; set; } = PublicKeyCredentialType.PublicKey;

        public PublicKeyAlgorithmEnum Algorithm { get; set; }
    }
}
