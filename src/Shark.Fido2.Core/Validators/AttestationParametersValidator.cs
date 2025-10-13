using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Validators;

public sealed class AttestationParametersValidator : IAttestationParametersValidator
{
    private const int MaxUserNameLength = 64;
    private const int MaxDisplayNameLength = 64;

    public void Validate(PublicKeyCredentialCreationOptionsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.UserName);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(request.DisplayName);

        if (request.UserName.Length > MaxUserNameLength)
        {
            throw new ArgumentException(
                $"Username cannot be more than {MaxUserNameLength} characters",
                nameof(request));
        }

        if (request.DisplayName.Length > MaxDisplayNameLength)
        {
            throw new ArgumentException(
                $"Display name be more than {MaxDisplayNameLength} characters",
                nameof(request));
        }
    }

    public AttestationCompleteResult Validate(
        PublicKeyCredentialAttestation attestation,
        PublicKeyCredentialCreationOptions creationOptions)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(attestation.Id);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(attestation.RawId);

        ArgumentNullException.ThrowIfNull(creationOptions);
        ArgumentNullException.ThrowIfNull(creationOptions.RelyingParty);
        ArgumentNullException.ThrowIfNull(creationOptions.User);
        ArgumentNullException.ThrowIfNull(creationOptions.PublicKeyCredentialParams);
        ArgumentNullException.ThrowIfNull(creationOptions.ExcludeCredentials);
        ArgumentNullException.ThrowIfNull(creationOptions.AuthenticatorSelection);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(creationOptions.Attestation);

        if (!attestation.Id.IsBase64Url())
        {
            return AttestationCompleteResult.CreateFailure("Attestation identifier is not Base64URL-encoded");
        }

        if (!string.Equals(attestation.Type, PublicKeyCredentialType.PublicKey))
        {
            return AttestationCompleteResult.CreateFailure("Attestation type is not set to \"public-key\"");
        }

        return AttestationCompleteResult.Create();
    }
}
