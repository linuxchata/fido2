using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Shark.Fido2.Core.Converters
{
    /// <summary>
    /// Converter for Concise Binary Object Representation
    /// </summary>
    public static class CborConverter
    {
        public static Dictionary<string, object> Decode(string value)
        {
            var valueBytes = Convert.FromBase64String(value);

            var reader = new CborReader(valueBytes);
            var result = Read(reader) as Dictionary<string, object>;

            return result ?? throw new ArgumentException("Failed to decode data from CBOR format");
        }

        public static Dictionary<string, object> ParseCoseKey(byte[] coseKeyBytes)
        {
            var result = new Dictionary<string, object>();

            var reader = new CborReader(coseKeyBytes);
            var mapLength = reader.ReadStartMap();

            for (var i = 0; i < mapLength; i++)
            {
                var key = reader.ReadInt32(); // Keys are integers in COSE_Key format

                // Map the integer key to human-readable name
                string keyName = key switch
                {
                    1 => "Key Type",
                    3 => "Algorithm",
                    -1 => "Curve",
                    -2 => "X-coordinate",
                    -3 => "Y-coordinate",
                    -4 => "Private Key",
                    _ => $"Unknown Key ({key})"
                };

                object? value = null;

                switch (reader.PeekState())
                {
                    case CborReaderState.UnsignedInteger:
                    case CborReaderState.NegativeInteger:
                        value = reader.ReadInt32();
                        break;
                    case CborReaderState.ByteString:
                        value = reader.ReadByteString();
                        break;
                    default:
                        break;
                }

                result[keyName] = value;
            }

            reader.ReadEndMap();
            return result;
        }

        private static object Read(CborReader reader)
        {
            switch (reader.PeekState())
            {
                case CborReaderState.TextString:
                    return reader.ReadTextString();
                case CborReaderState.ByteString:
                    return reader.ReadByteString();
                case CborReaderState.StartMap:
                    var result = new Dictionary<string, object>();
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        var key = reader.ReadTextString();
                        var value = Read(reader);
                        result[key] = value;
                    }
                    reader.ReadEndMap();
                    return result;
                default:
                    throw new InvalidOperationException($"Unsupported CBOR type {reader.PeekState()}");
            }
        }
    }
}
