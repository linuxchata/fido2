using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Constants;

public static class CoseAlgorithms
{
    public readonly static HashSet<CoseAlgorithm> Required =
    [
        CoseAlgorithm.Es256,
        CoseAlgorithm.Rs256,
        CoseAlgorithm.Rs1,
    ];

    // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#other
    public readonly static HashSet<CoseAlgorithm> Extended =
    [
        CoseAlgorithm.Es256,  // Required
        CoseAlgorithm.EdDsa,  // Recommended
        CoseAlgorithm.Es384,  // Recommended
        CoseAlgorithm.Es512,  // Optional
        CoseAlgorithm.Ps256,  // Optional
        CoseAlgorithm.Ps384,  // Optional
        CoseAlgorithm.Ps512,  // Optional
        CoseAlgorithm.Es256K, // Optional
        CoseAlgorithm.Rs256,  // Required
        CoseAlgorithm.Rs384,  // Optional
        CoseAlgorithm.Rs512,  // Optional
        CoseAlgorithm.Rs1,    // Required
    ];
}
