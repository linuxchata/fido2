using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Portal.Services;

namespace Shark.Fido2.Portal.Pages;

public class CredentialsDetailsModel : PageModel
{
    private readonly ICredentialService _credentialService;

    public CredentialsDetailsModel(ICredentialService credentialService)
    {
        _credentialService = credentialService;
    }

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

    public async Task OnGet(string credentialId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(credentialId))
        {
            return;
        }

        var credential = await _credentialService.Get(credentialId.FromBase64Url(), cancellationToken);
        if (credential is null)
        {
            Response.Redirect("/");
            return;
        }

        CredentialId = credential.CredentialId;
        UserHandle = credential.UserHandle;
        Username = credential.Username;
        SignCount = credential.SignCount;
        Transports = credential.Transports;
    }
}