namespace Shark.Fido2.Domain
{
    public sealed class PublicKeyCredential
    {
        public string Id { get; set; }

        public string RawId { get; set; }

        public AuthenticatorAttestationResponse Response { get; set; }

        public string Type { get; set; }
    }
}

