using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Services;

internal sealed class SubjectAlternativeNameParserService : ISubjectAlternativeNameParserService
{
    private const string TpmManufacturerName = "TPMManufacturer=";
    private const string TpmModelName = "TPMModel=";
    private const string TpmVersionName = "TPMVersion=";

    public TpmIssuer Parse(X509SubjectAlternativeNameExtension subjectAlternativeNameExtension)
    {
        var asndata = new AsnEncodedData(subjectAlternativeNameExtension.Oid, subjectAlternativeNameExtension.RawData);
        var subjectAlternativeName = asndata.Format(true);

        var subjectAlternativeNameSplit = subjectAlternativeName.Split(
            [Environment.NewLine, "\n"],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var tpmManufacturer = string.Empty;
        var tpmModel = string.Empty;
        var tpmVersion = string.Empty;
        foreach (var item in subjectAlternativeNameSplit)
        {
            if (item.StartsWith(TpmManufacturerName, StringComparison.OrdinalIgnoreCase))
            {
                tpmManufacturer = item[TpmManufacturerName.Length..];
            }
            else if (item.StartsWith(TpmModelName, StringComparison.OrdinalIgnoreCase))
            {
                tpmModel = item[TpmModelName.Length..];
            }
            else if (item.StartsWith(TpmVersionName, StringComparison.OrdinalIgnoreCase))
            {
                tpmVersion = item[TpmVersionName.Length..];
            }
        }

        var tpmManufacturerValue = GetManufacturerValue(tpmManufacturer);

        return new TpmIssuer
        {
            Manufacturer = tpmManufacturer,
            ManufacturerValue = tpmManufacturerValue,
            Model = tpmModel,
            Version = tpmVersion,
        };
    }

    private static string GetManufacturerValue(ReadOnlySpan<char> input)
    {
        if (input.IsEmpty)
        {
            return string.Empty;
        }

        var startIndex = input.IndexOf(':') + 1;
        var endIndex = input[startIndex..].IndexOfAny(' ', '(');
        return endIndex == -1 ? input[startIndex..].ToString() : input[startIndex..(startIndex + endIndex)].ToString();
    }
}
