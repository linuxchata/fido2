using Shark.Fido2.Core.Results.Attestation;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Extensions;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Abstractions.Handlers;

/// <summary>
/// The interface representing the logic to handle assertion objects during a authentication.
/// </summary>
public interface IAssertionObjectHandler
{
    /// <summary>
    /// Handles the processing of an assertion object from a authentication response.
    /// </summary>
    /// <param name="authenticatorDataString">The authenticator data.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="clientData">The parsed client data.</param>
    /// <param name="credentialPublicKey">The public key of the credential.</param>
    /// <param name="extensionsClientOutputs">The client extension outputs.</param>
    /// <param name="requestOptions">The original request options.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    InternalResult<AuthenticatorData> Handle(
        string authenticatorDataString,
        string signature,
        ClientData clientData,
        CredentialPublicKey credentialPublicKey,
        AuthenticationExtensionsClientOutputs extensionsClientOutputs,
        PublicKeyCredentialRequestOptions requestOptions);
}
