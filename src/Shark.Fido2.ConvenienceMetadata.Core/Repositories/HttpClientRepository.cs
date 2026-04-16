using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions.Repositories;
using Shark.Fido2.ConvenienceMetadata.Core.Configurations;

namespace Shark.Fido2.ConvenienceMetadata.Core.Repositories;

[ExcludeFromCodeCoverage]
internal sealed class HttpClientRepository(
    IHttpClientFactory httpClientFactory,
    IOptions<ConvenienceMetadataServiceConfiguration> options) : IHttpClientRepository
{
    public async Task<string> GetConvenienceMetadataBlob(CancellationToken cancellationToken)
    {
        using var httpClient = httpClientFactory.CreateClient();
        await using var stream = await httpClient.GetStreamAsync(options.Value.MetadataBlobLocation, cancellationToken);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken);
    }
}
