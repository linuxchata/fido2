namespace Shark.Fido2.Domain.Tpm;

public sealed class TpmIssuer
{
    /// <summary>
    /// Gets a TPM manufacturer.
    /// </summary>
    public string? Manufacturer { get; init; }

    /// <summary>
    /// Gets a TPM manufacturer.
    /// </summary>
    public string? ManufacturerValue { get; init; }

    /// <summary>
    /// Gets a TPM part number.
    /// </summary>
    public string? Model { get; init; }

    /// <summary>
    /// Gets a TPM firmware version.
    /// </summary>
    public string? Version { get; init; }
}
