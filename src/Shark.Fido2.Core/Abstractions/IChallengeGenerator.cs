namespace Shark.Fido2.Core.Abstractions;

/// <summary>
/// The interface representing the logic to generate cryptographic challenge values.
/// </summary>
public interface IChallengeGenerator
{
    /// <summary>
    /// Gets a new cryptographic challenge value.
    /// </summary>
    /// <returns>A byte array containing the generated challenge.</returns>
    byte[] Get();
}
