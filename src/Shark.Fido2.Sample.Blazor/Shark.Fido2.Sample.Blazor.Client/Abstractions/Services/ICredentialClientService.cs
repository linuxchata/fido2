using Shark.Fido2.Sample.Blazor.Client.Models;
using Shark.Fido2.Sample.Blazor.Client.ViewModels;

namespace Shark.Fido2.Sample.Blazor.Client.Abstractions.Services;

public interface ICredentialClientService
{
    Task<ResultModel<CredentialDetailsViewModel>> Get(string credentialId, CancellationToken cancellationToken);
}
