namespace Shark.Fido2.Domain.Options;

/// <summary>
/// 5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
/// See: https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions.
/// </summary>
public sealed class PublicKeyCredentialCreationOptions
{
    public required PublicKeyCredentialRpEntity RelyingParty { get; set; }

    public required PublicKeyCredentialUserEntity User { get; set; }

    public required byte[] Challenge { get; set; }

    public required PublicKeyCredentialParameter[] PublicKeyCredentialParams { get; set; }

    public ulong Timeout { get; set; }

    public required PublicKeyCredentialDescriptor[] ExcludeCredentials { get; set; }

    public required AuthenticatorSelectionCriteria AuthenticatorSelection { get; set; }

    public required string Attestation { get; set; }

    public required AuthenticationExtensionsClientInputs Extensions { get; set; }
}
