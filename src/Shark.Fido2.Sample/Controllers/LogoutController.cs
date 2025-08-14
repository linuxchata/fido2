using Microsoft.AspNetCore.Mvc;
using Shark.Fido2.Sample.Abstractions.Services;

namespace Shark.Fido2.Sample.Controllers;

/// <summary>
/// Logout.
/// </summary>
[Route("[controller]")]
public class LogoutController(ILoginService loginService) : Controller
{
    /// <summary>
    /// Logs out the authenticated user.
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost]
    public async Task<IActionResult> Index()
    {
        await loginService.Logout(HttpContext);

        var returnUrl = Request.Headers.Referer.ToString();

        return !string.IsNullOrEmpty(returnUrl) ?
            Redirect(returnUrl) :
            RedirectToPage("/Index");
    }
}