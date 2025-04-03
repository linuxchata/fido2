using Shark.Fido2.Metadata.Core.Domain;
using Shark.Fido2.Metadata.Core.Models;

namespace Shark.Fido2.Metadata.Core.Mappers;

internal static class MetadataPayloadItemMapper
{
    public static MetadataPayloadItem? ToDomain(this MetadataBlobPayloadEntry? entry)
    {
        if (entry == null)
        {
            return null;
        }

        return new MetadataPayloadItem
        {
            Aaguid = entry.Aaguid!.Value,
            StatusReports = entry.StatusReports
                .Select(s => new Domain.StatusReport { Status = s.Status, EffectiveDate = s.EffectiveDate, })
                .ToArray(),
            AttestationTypes = entry.MetadataStatement?.AttestationTypes ?? [],
        };
    }

    public static MetadataPayloadItem? ToDomain(this MetadataStatement? entry)
    {
        if (entry == null)
        {
            return null;
        }

        return new MetadataPayloadItem
        {
            Aaguid = entry.Aaguid!,
            StatusReports = [],
            AttestationTypes = entry.AttestationTypes,
        };
    }
}
