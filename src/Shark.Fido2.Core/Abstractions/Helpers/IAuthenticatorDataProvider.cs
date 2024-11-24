using Shark.Fido2.Core.Models;

namespace Shark.Fido2.Core.Abstractions.Helpers
{
    public interface IAuthenticatorDataProvider
    {
        AuthenticatorDataModel? Get(byte[]? authenticatorData);
    }
}
