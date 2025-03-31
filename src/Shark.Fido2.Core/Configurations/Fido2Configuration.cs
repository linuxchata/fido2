namespace Shark.Fido2.Core.Configurations;

public sealed class Fido2Configuration
{
    public const string Name = nameof(Fido2Configuration);

    public required string Origin { get; set; }

    public required string RelyingPartyId { get; set; }

    public required string RelyingPartyIdName { get; set; }

    public ulong? Timeout { get; set; }

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
}
