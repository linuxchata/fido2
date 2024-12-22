namespace Shark.Fido2.Domain.Constants
{
    /// <summary>
    /// 5.4.6. Resident Key Requirement Enumeration
    /// https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    /// </summary>
    public static class ResidentKeyRequirement
    {
        public const string Discouraged = "discouraged";

        public const string Preferred = "preferred";

        public const string Required = "required";
    }
}
