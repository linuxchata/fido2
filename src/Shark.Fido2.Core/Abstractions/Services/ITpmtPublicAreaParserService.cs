using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface ITpmtPublicAreaParserService
{
    bool Parse(byte[] pubArea, out TpmtPublic tpmtPublic);
}
