﻿using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Validates the client data received during a WebAuthn ceremony.
/// </summary>
public interface IClientDataValidator
{
    /// <summary>
    /// Validates the client data against WebAuthn specification requirements.
    /// </summary>
    /// <param name="clientData">The client data to validate.</param>
    /// <param name="expectedChallenge">The challenge that was originally sent to the client.</param>
    /// <returns>A ValidatorInternalResult indicating whether the client data is valid.</returns>
    ValidatorInternalResult Validate(ClientData clientData, string expectedChallenge);
}
