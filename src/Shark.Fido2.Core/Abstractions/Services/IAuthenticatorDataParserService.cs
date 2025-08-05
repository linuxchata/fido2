using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse authenticator data.
/// </summary>
public interface IAuthenticatorDataParserService
{
    /// <summary>
    /// Parses authenticator data from a byte array.
    /// </summary>
    /// <param name="authenticatorDataArray">The byte array containing the authenticator data.</param>
    /// <returns>The parsed authenticator data if successful; otherwise, null.</returns>
    AuthenticatorData? Parse(byte[]? authenticatorDataArray);
}
