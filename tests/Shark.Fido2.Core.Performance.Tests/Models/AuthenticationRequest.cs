using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Performance.Tests.Models;

internal class AuthenticationRequest
{
    public required PublicKeyCredentialRequestOptions RequestOptions { get; set; }

    public required PublicKeyCredentialAssertion Assertion { get; set; }
}
