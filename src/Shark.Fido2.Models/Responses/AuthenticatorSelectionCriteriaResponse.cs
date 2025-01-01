namespace Shark.Fido2.Models.Responses
{
    public class AuthenticatorSelectionCriteriaResponse
    {
        public string AuthenticatorAttachment { get; set; } = null!;

        public string ResidentKey { get; set; } = null!;

        public bool RequireResidentKey { get; set; }

        public string UserVerification { get; set; } = null!;
    }
}
