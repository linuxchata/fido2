using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace Shark.Fido2.Core.Configurations;

public class Fido2ConfigurationValidator : IValidateOptions<Fido2Configuration>
{
    public ValidateOptionsResult Validate(string? name, Fido2Configuration options)
    {
        if (string.IsNullOrWhiteSpace(options.RelyingPartyId))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId must be defined in the configuration");
        }

        if (options.RelyingPartyId.StartsWith("https://") || options.RelyingPartyId.StartsWith("http://"))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId must not include scheme");
        }

        if (Regex.IsMatch(options.RelyingPartyId, @":\d+"))
        {
            return ValidateOptionsResult.Fail("RelyingPartyId must not include port number");
        }

        if (string.IsNullOrWhiteSpace(options.Origin))
        {
            return ValidateOptionsResult.Fail("Origin must be defined in the configuration");
        }

        return ValidateOptionsResult.Success;
    }
}