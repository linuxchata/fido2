using Shark.Fido2.Core.Configurations;

namespace Shark.Fido2.Core.Tests;

internal class Fido2ConfigurationBuilder
{
    internal static Fido2Configuration Build()
    {
        return new Fido2Configuration
        {
            RelyingPartyId = "localhost",
            RelyingPartyIdName = "Shark Corporation",
            Origins = ["localhost"],
        };
    }
}
