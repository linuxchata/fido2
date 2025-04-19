namespace Shark.Fido2.Core.Configurations;

public sealed class Fido2Configuration
{
    public const string Name = nameof(Fido2Configuration);

    /// <summary>
    /// Gets the Relying Party origin.
    /// </summary>
    public required string Origin { get; init; }

    /// <summary>
    /// Gets a valid domain string identifying the Relying Party.
    /// </summary>
    public required string RelyingPartyId { get; init; }

    /// <summary>
    /// Gets a name of the Relying Party.
    /// </summary>
    public required string RelyingPartyIdName { get; init; }

    /// <summary>
    /// Gets a time, in milliseconds, that the caller is willing to wait for the call to complete.
    /// </summary>
    public ulong? Timeout { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether None attestation type is acceptable under Relying Party policy.
    /// </summary>
    public bool AllowNoneAttestation { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether Self attestation type is acceptable under Relying Party policy.
    /// </summary>
    public bool AllowSelfAttestation { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party trusts only keys that are securely generated
    /// and stored in a Trusted Execution Environment (Android Key Attestation).
    /// </summary>
    public bool EnableTrustedExecutionEnvironmentOnly { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party uses the Metadata Service to verify the attestation object.
    /// </summary>
    public bool EnableMetadataService { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party requires strict verification of authenticators.
    /// </summary>
    public bool EnableStrictAuthenticatorVerification { get; set; } = false;

    /// <summary>
    /// Gets a FIDO AppID extension.
    /// </summary>
    public string? AppId { get; init; }

    /// <summary>
    /// Gets a FIDO AppID Exclusion extension.
    /// </summary>
    public string? AppIdExclude { get; init; }

    /// <summary>
    /// Gets or sets a value indicating whether User Verification Method Extension (uvm) must be used.
    /// </summary>
    public bool UseUserVerificationMethod { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether Credential Properties Extension (credProps) must be used.
    /// </summary>
    public bool UseCredentialProperties { get; set; } = false;
}
