using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses
{
    public sealed class UserResponse
    {
        [JsonPropertyName("id")]
        public string Identifier { get; set; } = null!;

        [JsonPropertyName("name")]
        public string Name { get; set; } = null!;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = null!;
    }
}
