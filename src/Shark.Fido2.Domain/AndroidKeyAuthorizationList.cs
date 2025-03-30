namespace Shark.Fido2.Domain;

/// <summary>
/// Represents an Android Key authorization list containing key purpose, application scope, and origin information.
/// See: https://source.android.com/docs/security/features/keystore/attestation#authorization-list.
/// </summary>
public sealed class AndroidKeyAuthorizationList
{
    /// <summary>
    /// Gets the key purpose.
    /// </summary>
    public int Purpose { get; init; }

    /// <summary>
    /// Gets a value indicating whether the key is usable by all applications.
    /// </summary>
    public bool IsAllApplicationsPresent { get; init; }

    /// <summary>
    /// Gets the key origin.
    /// </summary>
    public int Origin { get; init; }
}
