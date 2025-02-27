namespace Shark.Fido2.Core.Configurations;

public sealed class Fido2Configuration
{
    public const string Name = nameof(Fido2Configuration);

    public string Origin { get; set; } = null!;

    public string RelyingPartyId { get; set; } = null!;

    public string RelyingPartyIdName { get; set; } = null!;

    public ulong? Timeout { get; set; }

    /// <summary>
    /// Gets or sets whether None attestation type is acceptable under Relying Party policy
    /// </summary>
    public bool AllowNoneAttestation { get; set; } = true;

    /// <summary>
    /// Gets or sets whether Self attestation type is acceptable under Relying Party policy
    /// </summary>
    public bool AllowSelfAttestation { get; set; } = true;
}
