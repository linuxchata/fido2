using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace Shark.Fido2.Sample.Controllers;

/// <summary>
/// Logout controller.
/// </summary>
[Route("[controller]")]
public class LogoutController : Controller
{
    /// <summary>
    /// Logs out the authenticated user.
    /// </summary>
    /// <returns>The HTTP response.</returns>
    [HttpPost]
    public async Task<IActionResult> Index()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToPage("/Index");
    }
}