using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate attestation parameters.
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
    /// <param name="publicKeyCredentialAttestation">The credential attestation response.</param>
    /// <param name="creationOptions">The original creation options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    AttestationCompleteResult Validate(
        PublicKeyCredentialAttestation publicKeyCredentialAttestation,
        PublicKeyCredentialCreationOptions creationOptions);
}
