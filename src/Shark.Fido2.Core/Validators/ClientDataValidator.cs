using Microsoft.Extensions.Options;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Configurations;
using Shark.Fido2.Core.Constants;
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

    public ValidatorInternalResult ValidateForAttestation(ClientData clientData, string expectedChallenge)
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
        if (!string.Equals(expectedChallenge, clientData.Challenge, StringComparison.Ordinal))
        {
            return ValidatorInternalResult.Invalid("Challenge mismatch");
        }

        // Step 9
        // Verify that the value of C.origin matches the Relying Party's origin.
        var result = ValidateOrigin(clientData);
        if (!result.IsValid)
        {
            return result;
        }

        // Step 10
        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
        // over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
        // C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        result = ValidateTokenBinding(clientData);
        if (!result.IsValid)
        {
            return result;
        }

        return ValidatorInternalResult.Valid();
    }

    public ValidatorInternalResult ValidateForAssertion(ClientData clientData, string expectedChallenge)
    {
        // 7.2. Verifying an Authentication Assertion

        // Step 11
        // Verify that the value of C.type is the string webauthn.get.
        if (!string.Equals(clientData.Type, WebAuthnType.Get, StringComparison.OrdinalIgnoreCase))
        {
            return ValidatorInternalResult.Invalid(
                $"Client data type mismatch. Expected type is {WebAuthnType.Get}");
        }

        // Step 12
        // Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        if (!string.Equals(expectedChallenge, clientData.Challenge, StringComparison.Ordinal))
        {
            return ValidatorInternalResult.Invalid("Challenge mismatch");
        }

        // Step 13
        // Verify that the value of C.origin matches the Relying Party's origin.
        var result = ValidateOrigin(clientData);
        if (!result.IsValid)
        {
            return result;
        }

        // Step 14
        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
        // over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify
        // that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        result = ValidateTokenBinding(clientData);
        if (!result.IsValid)
        {
            return result;
        }

        return ValidatorInternalResult.Valid();
    }

    private ValidatorInternalResult ValidateOrigin(ClientData clientData)
    {
        if (!Uri.TryCreate(clientData.Origin, UriKind.Absolute, out var originUri))
        {
            return ValidatorInternalResult.Invalid("Invalid client data origin");
        }

        if (_configuration.Origins.All(o => !string.Equals(originUri.Host, o, StringComparison.OrdinalIgnoreCase)))
        {
            return ValidatorInternalResult.Invalid("Client data origin mismatch");
        }

        return ValidatorInternalResult.Valid();
    }

    private static ValidatorInternalResult ValidateTokenBinding(ClientData clientData)
    {
        if (clientData.TokenBinding != null)
        {
            // TokenBindingStatusConverter checks whether status is supported
            if (clientData.TokenBinding.Status == TokenBindingStatus.Present &&
                string.IsNullOrWhiteSpace(clientData.TokenBinding.Id))
            {
                return ValidatorInternalResult.Invalid(
                    "Token binding identifier is not found for 'present' token binding status");
            }

            // Since browser support for Token Binding remains limited, further validation is not performed.
        }

        return ValidatorInternalResult.Valid();
    }
}
