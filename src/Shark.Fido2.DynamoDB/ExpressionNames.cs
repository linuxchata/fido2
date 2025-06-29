namespace Shark.Fido2.DynamoDB;

/// <summary>
/// Contains constants for DynamoDB expression names used in the credential repository.
/// </summary>
internal static class ExpressionNames
{
    /// <summary>
    /// User name expression parameter.
    /// </summary>
    public const string UserName = ":userName";

    /// <summary>
    /// Sign count expression parameter.
    /// </summary>
    public const string SignCount = ":signCount";

    /// <summary>
    /// Updated at timestamp expression parameter.
    /// </summary>
    public const string UpdatedAt = ":updatedAt";
}