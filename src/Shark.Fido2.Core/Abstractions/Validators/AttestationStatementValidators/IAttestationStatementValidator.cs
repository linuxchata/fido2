﻿using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Validates attestation statements in FIDO2 authentication process.
/// </summary>
public interface IAttestationStatementValidator
{
    /// <summary>
    /// Validates the attestation statement using the appropriate validation strategy based on the format.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the statement to validate.</param>
    /// <param name="clientData">The client data associated with the attestation.</param>
    /// <exception cref="ArgumentNullException">Thrown when attestationObjectData is null or attestation statement format is empty.</exception>
    /// <exception cref="ArgumentException">Thrown when attestation statement format is not supported.</exception>
    void Validate(AttestationObjectData attestationObjectData, ClientData clientData);
}
