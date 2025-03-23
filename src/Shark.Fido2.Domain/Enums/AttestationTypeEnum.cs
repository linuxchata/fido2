namespace Shark.Fido2.Domain.Enums;

public enum AttestationTypeEnum
{
    /// <summary>
    /// Basic Attestation
    /// </summary>
    Basic = 1,

    /// <summary>
    /// Self Attestation
    /// </summary>
    Self = 2,

    /// <summary>
    /// Attestation CA
    /// </summary>
    AttCA = 3,

    /// <summary>
    /// Anonymization CA
    /// </summary>
    AnonCA = 4,

    /// <summary>
    /// No attestation statement
    /// </summary>
    None = 5,
}
