using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface IJwsResponseParserService
{
    JwsResponse? Parse(byte[] response);
}
