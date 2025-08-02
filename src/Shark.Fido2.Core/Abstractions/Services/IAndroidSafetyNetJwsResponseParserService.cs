using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// Parses Android SafetyNet JWS (JSON Web Signature) responses.
/// </summary>
public interface IAndroidSafetyNetJwsResponseParserService
{
    /// <summary>
    /// Parses the given byte array containing a SafetyNet JWS response.
    /// </summary>
    /// <param name="response">The byte array representation of the JWS response.</param>
    /// <returns>The <see cref="JwsResponse"/> object if parsing is successful; otherwise, <c>null</c>.</returns>
    JwsResponse? Parse(byte[] response);
}
