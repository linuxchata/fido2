namespace Shark.Fido2.Core.Constants;

internal static class CoseAlgorithmsSet
{
    public const string Required = nameof(Required);

    public const string Recommended = nameof(Recommended);

    public const string Extended = nameof(Extended);

    public static readonly HashSet<string> Supported = [Required, Recommended, Extended];
}
