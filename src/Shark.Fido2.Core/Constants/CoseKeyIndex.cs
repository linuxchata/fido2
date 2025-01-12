namespace Shark.Fido2.Core.Constants
{
    /// <summary>
    /// COSE Key Objects
    /// https://datatracker.ietf.org/doc/html/rfc8152#section-7
    /// </summary>
    internal static class CoseKeyIndex
    {
        public const int KeyType = 1;

        public const int Algorithm = 3;

        public const int Modulus = -1;

        public const int Exponent = -2;

        public const int Curve = -1;

        public const int XCoordinate = -2;

        public const int YCoordinate = -3;
    }
}
