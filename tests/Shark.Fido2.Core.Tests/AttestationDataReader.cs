using System.Text.Json;

namespace Shark.Fido2.Core.Tests;

internal static class AttestationDataReader
{
    internal static AttestationData? Read(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var testDataPath = Path.Combine(baseDirectory, "Data", fileName);
        var testData = File.ReadAllText(testDataPath);
        return JsonSerializer.Deserialize<AttestationData>(testData);
    }
}
