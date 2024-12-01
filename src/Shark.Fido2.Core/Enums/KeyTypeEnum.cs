namespace Shark.Fido2.Core.Enums
{
    internal enum KeyTypeEnum
    {
        /// <summary>
        /// Octet Key Pair
        /// </summary>
        Okp = 1,

        /// <summary>
        /// Elliptic Curve keys
        /// </summary>
        Ec2 = 2,

        /// <summary>
        /// RSA keys
        /// </summary>
        Rsa = 3,

        /// <summary>
        /// Symmetric keys
        /// </summary>
        Symmetric = 4,
    }
}
