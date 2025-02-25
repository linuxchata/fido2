using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators;

internal class ClientDataValidator : IClientDataValidator
{
    private readonly Fido2Configuration _configuration;

    public ClientDataValidator(IOptions<Fido2Configuration> options)
    {
        _configuration = options.Value;
    }

    public ValidatorInternalResult Validate(ClientData clientData, string expectedChallenge)
    {
        // 7.1. Registering a New Credential (Steps 7 to 10)

        // Step 7
        // Verify that the value of C.type is webauthn.create.
        if (!string.Equals(clientData.Type, WebAuthnType.Create, StringComparison.OrdinalIgnoreCase))
        {
            return ValidatorInternalResult.Invalid(
                $"Client data type mismatch. Expected type is {WebAuthnType.Create}");
        }

        // Step 8
        // Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        var base64StringChallenge = Base64UrlConverter.ToBase64(clientData.Challenge!);
        if (!Base64Comparer.Compare(expectedChallenge!, base64StringChallenge))
        {
            return ValidatorInternalResult.Invalid("Challenge mismatch");
        }

        // Step 9
        // Verify that the value of C.origin matches the Relying Party's origin.
        if (!Uri.TryCreate(clientData.Origin, UriKind.Absolute, out var originUri))
        {
            return ValidatorInternalResult.Invalid("Invalid client data origin");
        }

        var expectedOrigin = _configuration.Origin;

        if (!string.Equals(originUri.Host, expectedOrigin, StringComparison.OrdinalIgnoreCase))
        {
            return ValidatorInternalResult.Invalid("Client data origin mismatch");
        }

        // Step 10
        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
        // over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        // C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        if (clientData.TokenBinding != null)
        {
            // TokenBindingStatusConverter checks whether status is supported

            if (clientData.TokenBinding.Status == TokenBindingStatus.Present &&
                string.IsNullOrWhiteSpace(clientData.TokenBinding.Id))
            {
                return ValidatorInternalResult.Invalid(
                    "Token binding identifier is not found for 'present' token binding status");
            }

            // TODO: Implement
        }

        return ValidatorInternalResult.Valid();
    }
}
