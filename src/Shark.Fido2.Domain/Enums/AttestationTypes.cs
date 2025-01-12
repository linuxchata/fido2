namespace Shark.Fido2.Domain.Enums
{
    public enum AttestationTypes
    {
        // Basic Attestation
        Basic = 1,

        // Self Attestation
        Self = 2,

        // Attestation CA
        AttCA = 3,

        // Anonymization CA
        AnonCA = 4,

        // No attestation statement
        None = 5,
    }
}
