using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Helpers
{
    public interface IAuthenticatorDataProvider
    {
        AuthenticatorData? Get(byte[]? authenticatorDataArray);
    }
}
