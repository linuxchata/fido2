using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests;

internal static class PublicKeyCredentialRequestOptionsBuilder
{
    internal static PublicKeyCredentialRequestOptions Build()
    {
        return new PublicKeyCredentialRequestOptions
        {
            Challenge = new byte[32],
        };
    }
}
