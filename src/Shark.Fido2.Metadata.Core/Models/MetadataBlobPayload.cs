namespace Shark.Fido2.Metadata.Core.Models;

public sealed class MetadataBlobPayload
{
    public required List<MetadataBlobPayloadEntry> Payload { get; init; }

    public DateTime NextUpdate { get; init; }

    public int Number { get; init; }
}
