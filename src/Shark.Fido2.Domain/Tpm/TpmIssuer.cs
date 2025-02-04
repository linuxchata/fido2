namespace Shark.Fido2.Domain.Tpm;

public sealed class TpmIssuer
{
    /// <summary>
    /// TPM manufacturer
    /// </summary>
    public string? Manufacturer { get; init; }

    /// <summary>
    /// TPM manufacturer
    /// </summary>
    public string? ManufacturerValue { get; init; }

    /// <summary>
    /// TPM part number
    /// </summary>
    public string? Model { get; init; }

    /// <summary>
    /// TPM firmware version
    /// </summary>
    public string? Version { get; init; }
}
