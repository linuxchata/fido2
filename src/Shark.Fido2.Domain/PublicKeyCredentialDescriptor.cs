using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain
{
    public class PublicKeyCredentialDescriptor
    {
        public string Type { get; set; } = PublicKeyCredentialType.PublicKey;

        public byte[] Id { get; set; } = null!;

        public AuthenticatorTransport[]? Transports { get; set; }
    }
}
