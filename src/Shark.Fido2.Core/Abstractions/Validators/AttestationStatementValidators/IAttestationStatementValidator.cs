﻿using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Defines the contract for validating attestation statements in FIDO2 WebAuthn responses.
/// An attestation statement is a specific type of signed data object that provides cryptographic proof about the authenticator
/// and the credentials it creates.
/// </summary>
public interface IAttestationStatementValidator
{
    /// <summary>
    /// Validates the attestation statement within an attestation object against the client data.
    /// </summary>
    /// <param name="attestationObjectData">The attestation object data containing the attestation statement to validate.</param>
    /// <param name="clientData">The client data associated with the attestation, used for verification.</param>
    /// <returns>A <see cref="ValidatorInternalResult"/> indicating whether the attestation statement is valid and any associated validation details.</returns>
    ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData);
}
