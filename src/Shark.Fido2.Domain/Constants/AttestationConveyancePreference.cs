namespace Shark.Fido2.Domain.Constants
{
    /// <summary>
    /// 5.4.7. Attestation Conveyance Preference Enumeration
    /// https://www.w3.org/TR/webauthn-2/#enum-attestation-convey
    /// </summary>
    public static class AttestationConveyancePreference
    {
        public const string None = "none";

        public const string Indirect = "indirect";

        public const string Direct = "direct";

        public const string Enterprise = "enterprise";
    }
}
