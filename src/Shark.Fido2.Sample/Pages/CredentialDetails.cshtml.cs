using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Fido2.ConvenienceMetadata.Core.Abstractions;
using Shark.Fido2.Sample.Abstractions.Services;

namespace Shark.Fido2.Sample.Pages;

[Authorize]
public class CredentialsDetailsModel : PageModel
{
    private const string DateTimeFormat = "yyyy-MM-dd HH:mm:ss";
    private readonly IConvenienceMetadataCachedService _convenienceMetadataService;

    private readonly ICredentialService _credentialService;

    public CredentialsDetailsModel(
        ICredentialService credentialService,
        IConvenienceMetadataCachedService convenienceMetadataService)
    {
        _credentialService = credentialService;
        _convenienceMetadataService = convenienceMetadataService;
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
    public required string AaGuid { get; set; }

    [BindProperty]
    public string? Authenticator { get; set; }

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

        var credential = await _credentialService.Get(credentialId, cancellationToken);
        if (credential is null)
        {
            Response.Redirect("/");
            return;
        }

        var authenticator = await _convenienceMetadataService.Get(credential.AaGuid, cancellationToken);
        var authenticatorName = authenticator?.GetDefaultName();

        CredentialId = credential.CredentialId;
        UserHandle = credential.UserHandle;
        UserName = credential.UserName;
        UserDisplayName = credential.UserDisplayName;
        AaGuid = $"{credential.AaGuid}";
        Authenticator = authenticatorName;
        SignCount = credential.SignCount;
        Algorithm = PublicKeyAlgorithms.Get(credential.CredentialPublicKey.Algorithm);
        Transports = credential.Transports;
        CreatedAt = credential.CreatedAt.ToString(DateTimeFormat, CultureInfo.InvariantCulture);
        UpdatedAt = credential.UpdatedAt?.ToString(DateTimeFormat, CultureInfo.InvariantCulture) ?? "-";
        LastUsedAt = credential.LastUsedAt?.ToString(DateTimeFormat, CultureInfo.InvariantCulture) ?? "-";
    }
}