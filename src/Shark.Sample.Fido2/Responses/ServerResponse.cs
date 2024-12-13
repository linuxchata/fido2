using System.Text.Json.Serialization;

namespace Shark.Sample.Fido2.Responses;

public class ServerResponse
{
    [JsonPropertyName("status")]
    public required string Status { get; set; }

    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }

    public static ServerResponse Create()
    {
        return new ServerResponse
        {
            Status = "ok",
        };
    }

    public static ServerResponse CreateFailed(string? errorMessage = null)
    {
        return new ServerResponse
        {
            Status = "failed",
            ErrorMessage = errorMessage,
        };
    }
}