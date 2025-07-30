using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// Defines methods for validating attestation parameters during WebAuthn registration.
/// </summary>
public interface IAttestationParametersValidator
{
    /// <summary>
    /// Validates the attestation parameters provided in the creation options request.
    /// </summary>
    /// <param name="request">The request containing parameters for generating credential creation options.</param>
    void Validate(PublicKeyCredentialCreationOptionsRequest request);

    /// <summary>
    /// Validates the attestation response and creation options.
    /// </summary>
    /// <param name="publicKeyCredentialAttestation">The credential attestation response received from the client.</param>
    /// <param name="creationOptions">The original creation options that were sent to the client.</param>
    /// <returns>An <see cref="AttestationCompleteResult"/> indicating the outcome of the validation.</returns>
    AttestationCompleteResult Validate(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions);
}
