using Shark.Fido2.Core.Constants;

namespace Shark.Fido2.Core.Configurations;

public sealed class Fido2Configuration
{
    public const string Name = nameof(Fido2Configuration);

    /// <summary>
    /// Gets a valid domain string identifying the Relying Party on whose behalf a given registration or authentication
    /// ceremony is being performed. This is a critical parameter in the WebAuthn standard. It defines the security
    /// scope within which credentials are valid. Therefore, careful selection is essential, as an incorrect or overly
    /// broad value can lead to unintended credential reuse or security vulnerabilities.
    /// </summary>
    public required string RelyingPartyId { get; init; }

    /// <summary>
    /// Gets a human-palatable identifier for the Relying Party, intended only for display.
    /// </summary>
    public required string RelyingPartyIdName { get; init; }

    /// <summary>
    /// Gets a list of fully qualified origins of the Relying Party making the request, passed to the authenticator by
    /// the browser.
    /// </summary>
    public required HashSet<string> Origins { get; init; }

    /// <summary>
    /// Gets a time, in milliseconds, that the Relying Party is willing to wait for the call to complete.
    /// </summary>
    public ulong? Timeout { get; init; }

    /// <summary>
    /// Gets or sets a set of the supported cryptographic algorithms.
    /// </summary>
    public string AlgorithmsSet { get; set; } = CoseAlgorithmsSet.Extended;

    /// <summary>
    /// Gets or sets a value indicating whether None attestation type is acceptable under Relying Party policy. None
    /// attestation is used when the authenticator doesn't have any attestation information available.
    /// </summary>
    public bool AllowNoneAttestation { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether Self attestation type is acceptable under Relying Party policy. Self
    /// attestation is used when the authenticator doesn't have a dedicated attestation key pair or a vendor-issued
    /// certificate.
    /// </summary>
    public bool AllowSelfAttestation { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party trusts only keys that are securely generated and
    /// stored in a Trusted Execution Environment (Android Key Attestation).
    /// </summary>
    public bool EnableTrustedExecutionEnvironmentOnly { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party uses the Metadata Service to verify the attestation object.
    /// </summary>
    public bool EnableMetadataService { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the Relying Party requires strict verification of authenticators. If
    /// enabled, missing metadata for the authenticator would cause attestation to fail.
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

    /// <summary>
    /// Gets or sets a value indicating whether Large blob storage extension (largeBlob) must be used.
    /// </summary>
    public bool UseLargeBlob { get; set; } = false;

    /// <summary>
    /// Gets or sets a value of the large blob support. Large blob storage extension (largeBlob) must be used.
    /// </summary>
    public string LargeBlobSupport { get; set; } = Constants.LargeBlobSupport.Preferred;
}