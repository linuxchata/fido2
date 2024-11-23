namespace Shark.Fido2.Core.Models
{
    public sealed class AuthenticatorDataModel
    {
        public byte[] RpIdHash { get; set; } = null!;

        public byte Flags { get; set; }

        public uint SignCount { get; set; }

        public string RpIdattestedCredentialDataHash { get; set; } = null!;

        public string Extensions { get; set; } = null!;
    }
}
