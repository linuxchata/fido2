namespace Shark.Fido2.Metadata.Core.Configurations;

public sealed class Fido2MetadataServiceConfiguration
{
    public const string Name = nameof(Fido2MetadataServiceConfiguration);

    public string MetadataBlobLocationUrl { get; set; } = "https://mds3.fidoalliance.org/";

    public string RootCertificateLocationUrl { get; set; } = "http://secure.globalsign.com/cacert/root-r3.crt";

    public int MaximumTokenSizeInBytes { get; set; } = 6_291_456;
}
