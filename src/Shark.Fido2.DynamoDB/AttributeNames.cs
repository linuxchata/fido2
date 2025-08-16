namespace Shark.Fido2.DynamoDB;

/// <summary>
/// Contains constants for DynamoDB attribute names used in the credential table.
/// </summary>
internal static class AttributeNames
{
    /// <summary>
    /// Credential identifier (partition key).
    /// </summary>
    public const string CredentialId = "cid";

    /// <summary>
    /// User handle.
    /// </summary>
    public const string UserHandle = "uh";

    /// <summary>
    /// User name (GSI partition key).
    /// </summary>
    public const string UserName = "un";

    /// <summary>
    /// User display name.
    /// </summary>
    public const string UserDisplayName = "udn";

    /// <summary>
    /// Credential public key JSON.
    /// </summary>
    public const string CredentialPublicKeyJson = "cpk";

    /// <summary>
    /// Sign count.
    /// </summary>
    public const string SignCount = "sc";

    /// <summary>
    /// Transports.
    /// </summary>
    public const string Transports = "tsp";

    /// <summary>
    /// Created at timestamp.
    /// </summary>
    public const string CreatedAt = "cat";

    /// <summary>
    /// Updated at timestamp.
    /// </summary>
    public const string UpdatedAt = "uat";

    /// <summary>
    /// Last sed at timestamp.
    /// </summary>
    public const string LastUsedAt = "luat";
}