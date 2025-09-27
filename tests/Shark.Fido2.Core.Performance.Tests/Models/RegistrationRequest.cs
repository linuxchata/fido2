using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Performance.Tests.Models;

internal class RegistrationRequest
{
    public required string Username { get; set; }

    public required byte[] CredentialId { get; set; }

    public required PublicKeyCredentialCreationOptions CreationOptions { get; set; }

    public required PublicKeyCredentialAttestation Attestation { get; set; }
}
