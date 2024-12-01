﻿namespace Shark.Fido2.Core.Enums
{
    /// <summary>
    /// COSE Algorithms
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    internal enum PublicKeyAlgorithmEnum
    {
        Es256 = -7,

        EdDsa = -8,

        Es384 = -35,

        Es512 = -36,

        Ps256 = -37,

        PS384 = -38,

        PS512 = -39,

        Rs256 = -257,
    }
}
