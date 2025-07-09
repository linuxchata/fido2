using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace Shark.Fido2.Core.Configurations;

public class Fido2ConfigurationValidator : IValidateOptions<Fido2Configuration>
{
    public ValidateOptionsResult Validate(string? name, Fido2Configuration options)
    {
        if (string.IsNullOrWhiteSpace(options.RelyingPartyId))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId configuration key must be defined");
        }

        if (options.RelyingPartyId.StartsWith("https://") || options.RelyingPartyId.StartsWith("http://"))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId configuration key must not include scheme");
        }

        if (Regex.IsMatch(options.RelyingPartyId, @":\d+"))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId configuration key must not include port number");
        }

        if (options.Origins.Count == 0)
        {
            return ValidateOptionsResult.Fail("Origins configuration key must include at least one origin");
        }

        if (options.Origins.Any(string.IsNullOrWhiteSpace))
        {
            return ValidateOptionsResult.Fail("Origins configuration key must not include empty values");
        }

        return ValidateOptionsResult.Success;
    }
}