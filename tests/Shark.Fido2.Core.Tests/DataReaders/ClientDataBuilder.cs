using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.DataReaders;

internal static class ClientDataBuilder
{
    internal static ClientData Build(string clientDataJson)
    {
        var clientDataJsonConverted = clientDataJson.FromBase64Url();

        return new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(clientDataJsonConverted),
        };
    }
}
