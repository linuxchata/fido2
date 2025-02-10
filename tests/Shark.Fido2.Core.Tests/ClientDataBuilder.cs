using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests;

internal static class ClientDataBuilder
{
    internal static ClientData Build(string clientDataJson)
    {
        return new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(Convert.FromBase64String(clientDataJson)),
        };
    }
}
