using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface ITpmsAttestationParserService
{
    bool Parse(byte[] certInfo, out TpmsAttestation tpmsAttestation);
}
