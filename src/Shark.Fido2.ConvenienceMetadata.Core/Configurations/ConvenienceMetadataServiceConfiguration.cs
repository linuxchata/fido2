using System.Diagnostics.CodeAnalysis;

namespace Shark.Fido2.ConvenienceMetadata.Core.Configurations;

[ExcludeFromCodeCoverage]
public sealed class ConvenienceMetadataServiceConfiguration
{
    public const string RootName = "Fido2Configuration";
    public const string Name = nameof(ConvenienceMetadataServiceConfiguration);

    /// <summary>
    /// Gets or sets a location of the convenience metadata service BLOB.
    /// </summary>
    public string ConvenienceMetadataBlobLocation { get; set; } = "https://c-mds.fidoalliance.org/";
}
