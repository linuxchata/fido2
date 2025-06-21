namespace Shark.Fido2.Core.Dictionaries;

/// <summary>
/// https://trustedcomputinggroup.org/resource/vendor-id-registry/
/// TCG TPM Vendor ID Registry Family 1.2 and 2.0
/// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf.
/// </summary>
internal static class TpmCapabilitiesVendors
{
    private static readonly Dictionary<string, string> Vendors = new()
    {
        { "414D4400", "AMD" },
        { "414E5400", "Ant Group" },
        { "41544D4C", "Atmel" },
        { "4252434D", "Broadcom" },
        { "4353434F", "Cisco" },
        { "464C5953", "Flyslice Technologies" },
        { "524F4343", "Fuzhou Rockchip" },
        { "474F4F47", "Google" },
        { "48504900", "HPI" },
        { "48504500", "HPE" },
        { "48495349", "Huawei" },
        { "49424D00", "IBM" },
        { "49465800", "Infineon" },
        { "494E5443", "Intel" },
        { "4C454E00", "Lenovo" },
        { "4D534654", "Microsoft" },
        { "4E534D20", "National Semiconductor" },
        { "4E545A00", "Nationz" },
        { "4E534700", "NSING" },
        { "4E544300", "Nuvoton Technology" },
        { "51434F4D", "Qualcomm" },
        { "534D534E", "Samsung" },
        { "53454345", "SecEdge" },
        { "534E5300", "Sinosun" },
        { "534D5343", "SMSC" },
        { "53544D20", "STMicroelectronics" },
        { "54584E00", "Texas Instruments" },
        { "57454300", "Winbond" },
        { "5345414C", "Wisekey" },
        { "FFFFF1D0", "Conformance Tools Test Vendor" },
    };

    public static bool Exists(string? verdonId)
    {
        if (string.IsNullOrWhiteSpace(verdonId))
        {
            return false;
        }

        return Vendors.TryGetValue(verdonId, out var _);
    }
}
