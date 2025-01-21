using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Shark.Fido2.Domain.Enums
{
    public class TokenBindingStatusConverter : JsonConverter<TokenBindingStatus>
    {
        public override TokenBindingStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var value = reader.GetString();
            return value switch
            {
                Constants.TokenBindingStatus.Present => TokenBindingStatus.Present,
                Constants.TokenBindingStatus.Supported => TokenBindingStatus.Supported,
                Constants.TokenBindingStatus.NotSupported => TokenBindingStatus.NotSupported,
                _ => throw new JsonException($"Unknown {nameof(TokenBindingStatus)} value: {value}")
            };
        }

        public override void Write(Utf8JsonWriter writer, TokenBindingStatus value, JsonSerializerOptions options)
        {
            var stringValue = value switch
            {
                TokenBindingStatus.Present => Constants.TokenBindingStatus.Present,
                TokenBindingStatus.Supported => Constants.TokenBindingStatus.Supported,
                TokenBindingStatus.NotSupported => Constants.TokenBindingStatus.NotSupported,
                _ => throw new ArgumentOutOfRangeException(nameof(value), $"Unknown {nameof(TokenBindingStatus)} value: {value}")
            };
            writer.WriteStringValue(stringValue);
        }
    }
}
