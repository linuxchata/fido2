namespace Shark.Fido2.Domain;

public class JwsResponse
{
    public required string RawToken { get; set; }

    public string? Algorithm { get; set; }

    public required List<object>? Certificates { get; set; }

    public string? Nonce { get; set; }

    public bool? CtsProfileMatch { get; set; }

    public bool? BasicIntegrity { get; set; }

    public string? ApkPackageName { get; set; }

    public string? ApkCertificateDigestSha256 { get; set; }

    public string? ApkDigestSha256 { get; set; }
}
