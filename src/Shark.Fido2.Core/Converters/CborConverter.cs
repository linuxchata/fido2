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
        public static Dictionary<string, object> Decode(string input)
        {
            var inputBytes = Convert.FromBase64String(input);

            var reader = new CborReader(inputBytes);
            var result = Read(reader) as Dictionary<string, object>;

            return result ?? throw new ArgumentException("Failed to decode data from CBOR format");
        }

        public static Dictionary<int, object> DecodeToCoseKeyFormat(byte[] input)
        {
            var result = new Dictionary<int, object>();

            var reader = new CborReader(input);
            var mapLength = reader.ReadStartMap();

            if (mapLength < 1)
            {
                throw new ArgumentException("Malformed COSE Key structure");
            }

            for (var i = 0; i < mapLength; i++)
            {
                var key = reader.ReadInt32();

                object value = null!;

                switch (reader.PeekState())
                {
                    case CborReaderState.UnsignedInteger:
                        value = reader.ReadUInt32();
                        break;
                    case CborReaderState.NegativeInteger:
                        value = reader.ReadInt32();
                        break;
                    case CborReaderState.ByteString:
                        value = reader.ReadByteString();
                        break;
                    default:
                        break;
                }

                result[key] = value;
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
                case CborReaderState.UnsignedInteger:
                    return reader.ReadUInt32();
                case CborReaderState.NegativeInteger:
                    return reader.ReadInt32();
                case CborReaderState.StartMap:
                    return ReadMap(reader);
                case CborReaderState.StartArray:
                    return ReadArray(reader);
                default:
                    throw new InvalidOperationException($"Unsupported CBOR type {reader.PeekState()}");
            }
        }

        private static object ReadMap(CborReader reader)
        {
            var map = new Dictionary<string, object>();
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();
                var value = Read(reader);
                map[key] = value;
            }
            reader.ReadEndMap();
            return map;
        }

        private static object ReadArray(CborReader reader)
        {
            var array = new List<object>();
            reader.ReadStartArray();
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                array.Add(Read(reader));
            }
            reader.ReadEndArray();
            return array;
        }
    }
}
