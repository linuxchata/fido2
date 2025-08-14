using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Shark.Fido2.Sample.Abstractions.Services;

namespace Shark.Fido2.Sample.Services;

public class LoginService : ILoginService
{
    private const string ProofOfPossessionKey = "pop";

    public async Task Login(HttpContext httpContext, string? username)
    {
        var claims = new Claim[]
        {
            new(ClaimTypes.Name, username ?? "Default User"),
            new(ClaimTypes.AuthenticationMethod, ProofOfPossessionKey),
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        await httpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            claimsPrincipal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1),
            });
    }
}
