using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Portal.Services;

namespace Shark.Fido2.Portal.Pages;

public class CredentialsDetailsModel : PageModel
{
    private const string DateTimeFormat = "yyyy-MM-dd HH:mm:ss";

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
    public required string UserName { get; set; }

    [BindProperty]
    public required string UserDisplayName { get; set; }

    [BindProperty]
    public uint SignCount { get; set; }

    [BindProperty]
    public required string Algorithm { get; set; }

    [BindProperty]
    public string[]? Transports { get; set; }

    [BindProperty]
    public required string CreatedAt { get; set; }

    [BindProperty]
    public string? UpdatedAt { get; set; }

    [BindProperty]
    public string? LastUsedAt { get; set; }

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
        UserName = credential.UserName;
        UserDisplayName = credential.UserDisplayName;
        SignCount = credential.SignCount;
        Algorithm = PublicKeyAlgorithms.Get(credential.CredentialPublicKey.Algorithm);
        Transports = credential.Transports;
        CreatedAt = credential.CreatedAt.ToString(DateTimeFormat, CultureInfo.InvariantCulture);
        UpdatedAt = credential.UpdatedAt?.ToString(DateTimeFormat, CultureInfo.InvariantCulture) ?? "-";
        LastUsedAt = credential.LastUsedAt?.ToString(DateTimeFormat, CultureInfo.InvariantCulture) ?? "-";
    }
}