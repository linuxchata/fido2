using System.Text.Json.Serialization;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Domain
{
    public sealed class TokenBinding
    {
        [JsonPropertyName("status")]
        public TokenBindingStatus Status { get; set; }

        [JsonPropertyName("id")]
        public string? Id { get; set; }
    }
}
