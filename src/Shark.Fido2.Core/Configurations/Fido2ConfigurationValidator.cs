using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Constants;

namespace Shark.Fido2.Core.Configurations;

public class Fido2ConfigurationValidator : IValidateOptions<Fido2Configuration>
{
    public ValidateOptionsResult Validate(string? name, Fido2Configuration options)
    {
        if (string.IsNullOrWhiteSpace(options.RelyingPartyId))
        {
            return ValidateOptionsResult.Fail("'RelyingPartyId' configuration key must be defined");
        }

        if (options.RelyingPartyId.StartsWith("https://") || options.RelyingPartyId.StartsWith("http://"))
        {
            return ValidateOptionsResult.Fail("'RelyingPartyId' configuration key must not include scheme");
        }

        if (Regex.IsMatch(options.RelyingPartyId, @":\d+", RegexOptions.None, TimeSpan.FromMilliseconds(100)))
        {
            return ValidateOptionsResult.Fail("'RelyingPartyId' configuration key must not include port number");
        }

        if (options.Origins == null || options.Origins.Count == 0)
        {
            return ValidateOptionsResult.Fail("'Origins' configuration key must include at least one origin");
        }

        if (options.Origins.Any(string.IsNullOrWhiteSpace))
        {
            return ValidateOptionsResult.Fail("'Origins' configuration key must not include empty values");
        }

        if (!string.IsNullOrWhiteSpace(options.AlgorithmsSet) &&
            !CoseAlgorithmsSet.Supported.Contains(options.AlgorithmsSet))
        {
            var supportedValues = string.Join(", ", CoseAlgorithmsSet.Supported);
            return ValidateOptionsResult.Fail(
                $"'AlgorithmsSet' configuration key must be one of the following values: {supportedValues}");
        }

        return ValidateOptionsResult.Success;
    }
}