namespace Shark.Fido2.Domain
{
    /// <summary>
    /// 5.4. Options for Credential Creation
    /// https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
    /// </summary>
    public sealed class PublicKeyCredentialCreationOptions
    {
        public PublicKeyCredentialRpEntity RelyingParty { get; set; } = null!;

        public string Challenge { get; set; } = null!;

        public uint Timeout { get; set; }
    }
}
