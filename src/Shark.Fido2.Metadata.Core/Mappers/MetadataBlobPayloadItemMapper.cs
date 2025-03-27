using Shark.Fido2.Metadata.Core.Models;
using Shark.Fido2.Metadata.Domain;

namespace Shark.Fido2.Metadata.Core.Mappers;

internal static class MetadataBlobPayloadItemMapper
{
    public static MetadataBlobPayloadItem? ToDomain(this MetadataBlobPayloadEntry? entry)
    {
        if (entry == null)
        {
            return null;
        }

        return new MetadataBlobPayloadItem
        {
            Aaguid = entry.Aaguid!.Value,
            StatusReports = entry.StatusReports
                .Select(s => new Domain.StatusReport
                {
                    Status = s.Status,
                    EffectiveDate = s.EffectiveDate,
                })
                .ToArray()
        };
    }
}
