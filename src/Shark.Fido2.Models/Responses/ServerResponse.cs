using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public class ServerResponse
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = null!;

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
}