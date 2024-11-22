using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Shark.Fido2.Core.Helpers
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

            return result ?? throw new ArgumentException("Data cannot be decoded with CBOR converter");
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
