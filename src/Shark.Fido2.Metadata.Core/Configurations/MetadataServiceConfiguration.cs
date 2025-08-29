namespace Shark.Fido2.Metadata.Core.Configurations;

public sealed class MetadataServiceConfiguration
{
    public const string Name = nameof(MetadataServiceConfiguration);

    /// <summary>
    /// Gets or sets a location of the centralized and trusted source of information about FIDO authenticators
    /// (Metadata Service BLOB).
    /// </summary>
    public string MetadataBlobLocation { get; set; } = "https://mds3.fidoalliance.org/";

    /// <summary>
    /// Gets or sets a location of GlobalSign Root R3 for Metadata Service BLOB.
    /// </summary>
    public string RootCertificateLocationUrl { get; set; } = "https://secure.globalsign.com/cacert/root-r3.crt";

    /// <summary>
    /// Gets or sets a maximum token size in bytes that will be processed. This configuration is related
    /// to the Metadata Service BLOB size.
    /// </summary>
    public int MaximumTokenSizeInBytes { get; set; } = 8_388_608;
}
