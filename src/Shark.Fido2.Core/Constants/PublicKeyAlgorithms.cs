using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Constants;

public static class PublicKeyAlgorithms
{
    public readonly static HashSet<PublicKeyAlgorithm> Default =
    [
        PublicKeyAlgorithm.Es256,
        PublicKeyAlgorithm.Rs256,
    ];

    // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#other
    public readonly static HashSet<PublicKeyAlgorithm> Extended =
    [
        PublicKeyAlgorithm.Es256,  // Required
        PublicKeyAlgorithm.EdDsa,  // Recommended
        PublicKeyAlgorithm.Es384,  // Recommended
        PublicKeyAlgorithm.Es512,  // Optional
        PublicKeyAlgorithm.Ps256,  // Optional
        PublicKeyAlgorithm.Ps384,  // Optional
        PublicKeyAlgorithm.Ps512,  // Optional
        PublicKeyAlgorithm.Es256K, // Optional
        PublicKeyAlgorithm.Rs256,  // Required
        PublicKeyAlgorithm.Rs384,  // Optional
        PublicKeyAlgorithm.Rs512,  // Optional
        PublicKeyAlgorithm.Rs1,    // Required
    ];
}
