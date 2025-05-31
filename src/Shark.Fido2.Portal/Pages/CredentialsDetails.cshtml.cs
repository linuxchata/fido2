using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Shark.Fido2.Portal.Pages;

public class CredentialsDetailsModel : PageModel
{
    [BindProperty]
    public required byte[] CredentialId { get; set; }

    [BindProperty]
    public required byte[] UserHandle { get; set; }

    [BindProperty]
    public required string Username { get; set; }

    [BindProperty]
    public uint SignCount { get; set; }

    [BindProperty]
    public string[]? Transports { get; set; }

    public void OnGet()
    {
    }
} 