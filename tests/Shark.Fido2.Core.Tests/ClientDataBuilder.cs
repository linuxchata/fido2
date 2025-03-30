using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests;

internal class ClientDataBuilder
{
    internal static ClientData Build(string clientDataJson)
    {
        var clientDataJsonConverted = clientDataJson.FromBase64Url();

        return new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = "challenge",
            Origin = "https://localhost:44300",
            ClientDataHash = HashProvider.GetSha256Hash(clientDataJsonConverted),
        };
    }

    internal static ClientData BuildCreate()
    {
        return new ClientData
        {
            Type = WebAuthnType.Create,
            Challenge = "challenge",
            Origin = "https://localhost:44300",
            ClientDataHash = [],
        };
    }

    internal static ClientData BuildGet()
    {
        return new ClientData
        {
            Type = WebAuthnType.Get,
            Challenge = "challenge",
            Origin = "https://localhost:44300",
            ClientDataHash = [],
        };
    }
}
