using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Services;

internal sealed class SubjectAlternativeNameParserService : ISubjectAlternativeNameParserService
{
    private const string TpmManufacturerName = "TPMManufacturer";
    private const string TpmManufacturerId = "2.23.133.2.1";
    private const string TpmModelName = "TPMModel";
    private const string TpmModelId = "2.23.133.2.2";
    private const string TpmVersionName = "TPMVersion";
    private const string TpmVersionId = "2.23.133.2.3";

    private readonly Regex _regexNumericNotation = new Regex(@"(?<key>\d+(\.\d+)+)=(?<value>[\w:]+)");
    private readonly Regex _regexNameNotation = new Regex(@"(?<key>\w+)=(?<value>[\w:]+)");
    private readonly Regex _regexManufacturer = new Regex(@"id:([A-F0-9]+)");

    public TpmIssuer Parse(X509SubjectAlternativeNameExtension subjectAlternativeNameExtension)
    {
        var encodedData = new AsnEncodedData(subjectAlternativeNameExtension.Oid, subjectAlternativeNameExtension.RawData);
        var subjectAlternativeName = encodedData.Format(false);

        return Parse(subjectAlternativeName);
    }

    internal TpmIssuer Parse(string subjectAlternativeName)
    {
        var matchesNumericNotation = _regexNumericNotation.Matches(subjectAlternativeName);
        var matchesNameNotation = _regexNameNotation.Matches(subjectAlternativeName);

        var matches = matchesNumericNotation.Count != 0 ? matchesNumericNotation : matchesNameNotation;

        var tpmManufacturer = string.Empty;
        var tpmModel = string.Empty;
        var tpmVersion = string.Empty;

        foreach (Match match in matches)
        {
            var key = match.Groups["key"].Value;
            var value = match.Groups["value"].Value;
            if (string.Equals(key, TpmVersionId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, TpmVersionName, StringComparison.OrdinalIgnoreCase))
            {
                tpmVersion = value;
            }
            else if (string.Equals(key, TpmModelId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, TpmModelName, StringComparison.OrdinalIgnoreCase))
            {
                tpmModel = value;
            }
            else if (string.Equals(key, TpmManufacturerId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, TpmManufacturerName, StringComparison.OrdinalIgnoreCase))
            {
                tpmManufacturer = value;
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

    private string GetManufacturerValue(string input)
    {
        var match = _regexManufacturer.Match(input);
        if (match.Success)
        {
            return match.Groups[1].Value;
        }

        return string.Empty;
    }
}
