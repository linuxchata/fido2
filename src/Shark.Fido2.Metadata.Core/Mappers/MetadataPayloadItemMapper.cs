﻿using Shark.Fido2.Metadata.Core.Domain;
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
            Description = entry.MetadataStatement?.Description,
            StatusReports = entry.StatusReports
                .Select(s => new Domain.StatusReport { Status = s.Status, EffectiveDate = s.EffectiveDate, })
                .ToArray(),
            AttestationTypes = entry.MetadataStatement?.AttestationTypes ?? [],
        };
    }
}
