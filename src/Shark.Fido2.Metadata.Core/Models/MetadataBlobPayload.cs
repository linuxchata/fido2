namespace Shark.Fido2.Metadata.Core.Models;

public sealed class MetadataBlobPayload
{
    public required List<MetadataBlobPayloadEntry> Payload { get; set; }

    public DateTime NextUpdate { get; set; }

    public int Number { get; set; }
}
