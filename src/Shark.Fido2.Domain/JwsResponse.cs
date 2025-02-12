namespace Shark.Fido2.Domain;

public class JwsResponse
{
    public required string RawToken { get; init; }

    public string? Algorithm { get; init; }

    public required List<object>? Certificates { get; init; }

    public string? Nonce { get; init; }

    public bool? CtsProfileMatch { get; init; }

    public bool? BasicIntegrity { get; init; }

    public string? ApkPackageName { get; init; }

    public string? ApkCertificateDigestSha256 { get; init; }

    public string? ApkDigestSha256 { get; init; }

    public string? TimestampMs { get; init; }
}
