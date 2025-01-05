using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain
{
    /// <summary>
    /// 5.5. Options for Assertion Generation
    /// https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    /// </summary>
    public sealed class PublicKeyCredentialRequestOptions
    {
        public byte[] Challenge { get; set; } = null!;

        public ulong Timeout { get; set; }

        public string RpId { get; set; } = null!;

        public PublicKeyCredentialDescriptor[] AllowCredentials { get; set; } = null!;

        public UserVerificationRequirement? UserVerification { get; set; }
    }
}
