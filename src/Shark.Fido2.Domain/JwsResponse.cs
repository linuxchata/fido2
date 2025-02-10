namespace Shark.Fido2.Domain;

public class JwsResponse
{
    public string? Algorithm { get; set; }

    public required List<object>? Certificates { get; set; }

    public string? Nonce { get; set; }
}
