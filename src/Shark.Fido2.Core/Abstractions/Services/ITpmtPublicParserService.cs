using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface ITpmtPublicParserService
{
    TpmtPublic Parse(byte[] pubArea);
}
