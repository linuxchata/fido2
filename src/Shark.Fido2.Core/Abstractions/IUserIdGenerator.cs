namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// The interface representing the logic to generate user identifiers.
/// </summary>
public interface IUserIdGenerator
{
    /// <summary>
    /// Gets a user identifier.
    /// </summary>
    /// <param name="seed">An optional seed string used to generate a deterministic user identifier.</param>
    /// <returns>A byte array representing the generated user identifier.</returns>
    byte[] Get(string? seed = null);
}
