using System.Text.Json;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Integration.Tests.DataReaders;

internal static class DataReader
{
    internal static PublicKeyCredentialCreationOptions ReadCreationOptions(string fileName)
    {
        var testData = GetTestData(fileName);
        var creationOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(testData)
            ?? throw new ArgumentException();

        return creationOptions;
    }

    internal static PublicKeyCredentialAttestation ReadAttestationData(string fileName)
    {
        var testData = GetTestData(fileName);
        var attestationData = JsonSerializer.Deserialize<PublicKeyCredentialAttestation>(testData)
            ?? throw new ArgumentException();

        return attestationData;
    }

    internal static PublicKeyCredentialRequestOptions ReadRequestOptions(string fileName)
    {
        var testData = GetTestData(fileName);
        var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(testData)
            ?? throw new ArgumentException();

        return requestOptions;
    }

    internal static PublicKeyCredentialAssertion ReadAssertionData(string fileName)
    {
        var testData = GetTestData(fileName);
        var assertionData = JsonSerializer.Deserialize<PublicKeyCredentialAssertion>(testData)
            ?? throw new ArgumentException();

        return assertionData;
    }

    private static string GetTestData(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var testDataPath = Path.Combine(baseDirectory, "Data", fileName);
        return File.ReadAllText(testDataPath);
    }
}
