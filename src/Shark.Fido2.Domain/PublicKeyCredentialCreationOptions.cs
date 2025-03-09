namespace Shark.Fido2.Domain;

/// <summary>
/// 5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
/// See: https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
/// </summary>
public sealed class PublicKeyCredentialCreationOptions
{
    public PublicKeyCredentialRpEntity RelyingParty { get; set; } = null!;

    public PublicKeyCredentialUserEntity User { get; set; } = null!;

    public byte[] Challenge { get; set; } = null!;

    public PublicKeyCredentialParameter[] PublicKeyCredentialParams { get; set; } = null!;

    public ulong Timeout { get; set; }

    public PublicKeyCredentialDescriptor[] ExcludeCredentials { get; set; } = null!;

    public AuthenticatorSelectionCriteria AuthenticatorSelection { get; set; } = null!;

    public string Attestation { get; set; } = null!;

    public AuthenticationExtensionsClientInputs Extensions { get; set; } = null!;
}
