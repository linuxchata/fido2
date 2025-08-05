using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse Android SafetyNet JWS (JSON Web Signature) responses.
/// </summary>
public interface IAndroidSafetyNetJwsResponseParserService
{
    /// <summary>
    /// Parses the given byte array containing a SafetyNet JWS response.
    /// </summary>
    /// <param name="response">The byte array representation of the JWS response.</param>
    /// <returns>The JSON response object if parsing is successful; otherwise, null.</returns>
    JwsResponse? Parse(byte[] response);
}
