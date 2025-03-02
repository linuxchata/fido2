using System.Text.Json;
using Shark.Fido2.Core.Tests.Models;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.DataReaders;

internal static class AttestationDataReader
{
    internal static PublicKeyCredentialAttestation Read(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var testDataPath = Path.Combine(baseDirectory, "Data", fileName);
        var testData = File.ReadAllText(testDataPath);
        var attestationData = JsonSerializer.Deserialize<AttestationData>(testData) ?? throw new ArgumentException();

        return new PublicKeyCredentialAttestation
        {
            Id = attestationData.Id,
            RawId = attestationData.RawId,
            Response = new AuthenticatorAttestationResponse
            {
                ClientDataJson = attestationData.Response.ClientDataJson,
                AttestationObject = attestationData.Response.AttestationObject,
                Transports = [],
            },
            Type = attestationData.Type,
        };
    }
}
