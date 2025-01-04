namespace Shark.Fido2.Domain
{
    public sealed class PublicKeyCredentialCreationOptionsRequest
    {
        public string Username { get; set; } = null!;

        public string DisplayName { get; set; } = null!;

        public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

        public string? Attestation { get; set; }
    }
}
