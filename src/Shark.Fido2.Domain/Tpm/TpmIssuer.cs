namespace Shark.Fido2.Domain.Tpm;

public sealed class TpmIssuer
{
    /// <summary>
    /// Gets a TPM manufacturer (2.23.133.2.1).
    /// </summary>
    public string? Manufacturer { get; init; }

    /// <summary>
    /// Gets a TPM manufacturer value (without 'id:').
    /// </summary>
    public string? ManufacturerValue { get; init; }

    /// <summary>
    /// Gets a TPM part number (2.23.133.2.2).
    /// </summary>
    public string? Model { get; init; }

    /// <summary>
    /// Gets a TPM firmware version (2.23.133.2.3).
    /// </summary>
    public string? Version { get; init; }
}
