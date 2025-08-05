using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Validators;

/// <summary>
/// The interface representing the logic to validate assertion objects.
/// </summary>
public interface IAssertionObjectValidator
{
    /// <summary>
    /// Validates an assertion object.
    /// </summary>
    /// <param name="authenticatorData">The authenticator data.</param>
    /// <param name="authenticatorRawData">The raw authenticator data.</param>
    /// <param name="clientDataHash">The hash of the client data.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="credentialPublicKey">The public key of the credential.</param>
    /// <param name="extensionsClientOutputs">The client extension outputs.</param>
    /// <param name="requestOptions">The original request options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(
        AuthenticatorData? authenticatorData,
        byte[] authenticatorRawData,
        byte[]? clientDataHash,
        string signature,
        CredentialPublicKey credentialPublicKey,
        AuthenticationExtensionsClientOutputs extensionsClientOutputs,
        PublicKeyCredentialRequestOptions requestOptions);
}
