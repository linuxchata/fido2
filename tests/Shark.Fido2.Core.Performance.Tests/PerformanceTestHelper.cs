using System.Globalization;
using System.Security.Cryptography;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Converters;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Performance.Tests.Models;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.Tests.Common;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Performance.Tests;

internal class PerformanceTestHelper
{
    private const string NoneAttestation = "NoneAttestation.json";
    private const string NoneCreationOptions = "NoneCreationOptions.json";
    private const string NoneAssertion = "NoneAssertion.json";
    private const string NoneRequestOptions = "NoneRequestOptions.json";

    private readonly UserIdGenerator _userIdGenerator;

    internal PerformanceTestHelper()
    {
        _userIdGenerator = new();
    }

    internal RegistrationRequest GenerateRegistrationRequest()
    {
        // Generate creation options
        var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);
        var username = $"Name_{Guid.NewGuid().ToString().ToLower(CultureInfo.CurrentCulture)}";
        creationOptions.User = new PublicKeyCredentialUserEntity
        {
            Id = _userIdGenerator.Get(username),
            Name = username,
            DisplayName = $"DisplayName_{Guid.NewGuid().ToString().ToLower(CultureInfo.CurrentCulture)}",
        };

        // Generate attestation data
        // Attestation data must be re-generate for each request to replace credential ID in attestation object
        var attestationData = DataReader.ReadAttestationData(NoneAttestation);

        var credentialId = GetCredentialId();
        attestationData.Id = credentialId.ToBase64Url();
        attestationData.RawId = credentialId.ToBase64Url();

        var decodedAttestationObject = CborConverter.Decode(attestationData.Response.AttestationObject);
        var authenticatorDataArray = decodedAttestationObject[AttestationObjectKey.AuthData] as byte[];
        var authenticatorData = new AuthenticatorDataParserService().Parse(authenticatorDataArray);
        var attestationObject = NoneAttestationGenerator.GenerateAttestationObject(authenticatorData!, credentialId);

        attestationData.Response = new AuthenticatorAttestationResponse
        {
            ClientDataJson = attestationData.Response.ClientDataJson,
            AttestationObject = attestationObject,
            Transports = attestationData.Response.Transports,
        };

        return new RegistrationRequest
        {
            Username = username,
            CredentialId = credentialId,
            CreationOptions = creationOptions,
            Attestation = attestationData,
        };
    }

    internal AuthenticationRequest GenerateAuthenticationRequest(string credentialId, string name)
    {
        // Generate request options
        var requestOptionsTemplate = DataReader.ReadRequestOptions(NoneRequestOptions);

        var requestOptions = new PublicKeyCredentialRequestOptions
        {
            Challenge = requestOptionsTemplate.Challenge,
            Timeout = requestOptionsTemplate.Timeout,
            RpId = requestOptionsTemplate.RpId,
            AllowCredentials =
            [
                new PublicKeyCredentialDescriptor
                {
                    Id = credentialId.FromBase64Url(),
                    Transports = [AuthenticatorTransport.Hybrid, AuthenticatorTransport.Internal],
                },
            ],
            UserVerification = requestOptionsTemplate.UserVerification,
            Username = name,
        };

        // Generate assertion data
        var assertionData = DataReader.ReadAssertionData(NoneAssertion);

        assertionData.Id = credentialId;
        assertionData.RawId = credentialId;
        assertionData.Response = new AuthenticatorAssertionResponse
        {
            ClientDataJson = assertionData.Response.ClientDataJson,
            AuthenticatorData = assertionData.Response.AuthenticatorData,
            Signature = assertionData.Response.Signature,
            UserHandle = _userIdGenerator.Get(name).ToBase64Url(),
        };

        return new AuthenticationRequest
        {
            RequestOptions = requestOptions,
            Assertion = assertionData,
        };
    }

    private byte[] GetCredentialId()
    {
        var credentialIdBytes = new byte[20];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(credentialIdBytes);
        return credentialIdBytes;
    }
}
