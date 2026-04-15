namespace Shark.Fido2.ConvenienceMetadata.Core.Configurations;

public sealed class ConvenienceMetadataServiceConfiguration
{
    public const string Name = nameof(ConvenienceMetadataServiceConfiguration);

    /// <summary>
    /// Gets or sets a location of the Convenience Metadata Service BLOB.
    /// </summary>
    public string MetadataBlobLocation { get; set; } = "https://c-mds.fidoalliance.org/";
}
