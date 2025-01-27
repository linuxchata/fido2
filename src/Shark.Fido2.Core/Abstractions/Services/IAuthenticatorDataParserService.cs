using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface IAuthenticatorDataParserService
{
    AuthenticatorData? Parse(byte[]? authenticatorDataArray);
}
