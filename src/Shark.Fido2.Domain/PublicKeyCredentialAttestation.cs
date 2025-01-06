namespace Shark.Fido2.Domain
{
    public sealed class PublicKeyCredentialAttestation
    {
        public string Id { get; set; } = null!;

        public string RawId { get; set; } = null!;

        public AuthenticatorAttestationResponse Response { get; set; } = null!;

        public string Type { get; set; } = null!;
    }
}
