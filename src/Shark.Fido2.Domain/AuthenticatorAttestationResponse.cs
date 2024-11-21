namespace Shark.Fido2.Domain
{
    public sealed class AuthenticatorAttestationResponse
    {
        public string ClientDataJson { get; set; }

        public string AttestationObject { get; set; }

        public string? Signature { get; set; }

        public string? UserHandler { get; set; }
    }
}