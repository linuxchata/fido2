using System.Text.Json;
using Shark.Fido2.Core.Tests.Models;

namespace Shark.Fido2.Core.Tests.DataReaders;

internal static class AttestationResponseDataReader
{
    internal static AttestationResponseData? Read(string fileName)
    {
        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var testDataPath = Path.Combine(baseDirectory, "Data", fileName);
        var testData = File.ReadAllText(testDataPath);
        return JsonSerializer.Deserialize<AttestationResponseData>(testData);
    }
}
