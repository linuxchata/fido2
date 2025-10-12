namespace Shark.Fido2.Domain.Extensions;

public sealed class AuthenticationExtensionsClientInputs
{
    /// <summary>
    /// Gets appid.<br/>
    /// Usage: Authentication.
    /// </summary>
    public string? AppId { get; init; }

    /// <summary>
    /// Gets appidExclude.<br/>
    /// Usage: Registration.
    /// </summary>
    public string? AppIdExclude { get; init; }

    /// <summary>
    /// Gets whether user verification method is enabled.<br/>
    /// Usage: Registration and Authentication.
    /// </summary>
    public bool? UserVerificationMethod { get; init; }

    /// <summary>
    /// Gets whether credProps are used.<br/>
    /// Usage: Registration.
    /// </summary>
    public bool? CredentialProperties { get; init; }

    /// <summary>
    /// Gets largeBlob.<br/>
    /// Usage: Registration.
    /// </summary>
    public AuthenticationExtensionsLargeBlobInputs? LargeBlob { get; init; }
}
