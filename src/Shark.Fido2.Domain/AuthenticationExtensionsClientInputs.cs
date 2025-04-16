namespace Shark.Fido2.Domain;

public sealed class AuthenticationExtensionsClientInputs
{
    /// <summary>
    /// Gets appid. Usage: authentication.
    /// </summary>
    public string? AppId { get; init; }

    /// <summary>
    /// Gets appidExclude. Usage: registration.
    /// </summary>
    public string? AppIdExclude { get; init; }

    /// <summary>
    /// Gets whether uvm is enabled. Usage: registration and authentication.
    /// </summary>
    public bool? UserVerificationMethod { get; init; }

    /// <summary>
    /// Gets whether credProps are used. Usage: registration.
    /// </summary>
    public bool? CredentialProperties { get; init; }

    /// <summary>
    /// Gets largeBlob. Usage: registration.
    /// </summary>
    public AuthenticationExtensionsLargeBlobInputs? LargeBlob { get; init; }
}
