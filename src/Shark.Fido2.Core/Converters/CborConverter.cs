using System.Formats.Cbor;
using Shark.Fido2.Common.Extensions;

namespace Shark.Fido2.Core.Converters;

/// <summary>
/// Converter for Concise Binary Object Representation.
/// </summary>
public static class CborConverter
{
    private const int MaxIterations = 10;

    public static Dictionary<string, object> Decode(string input)
    {
        var inputBytes = input.FromBase64Url();

        var reader = new CborReader(inputBytes);
        var result = Read(reader) as Dictionary<string, object>;

        return result ?? throw new ArgumentException("Failed to decode data from CBOR format");
    }

    public static Dictionary<string, object> Decode(byte[] input, ref int bytesRemaining)
    {
        var reader = new CborReader(input);
        var result = Read(reader) as Dictionary<string, object>;

        bytesRemaining = reader.BytesRemaining;

        return result ?? [];
    }

    public static Dictionary<int, object> DecodeToCoseKeyFormat(byte[] input, ref int bytesRemaining)
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

        bytesRemaining = reader.BytesRemaining;

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

    private static Dictionary<string, object> ReadMap(CborReader reader)
    {
        var map = new Dictionary<string, object>();
        reader.ReadStartMap();

        var counter = 0;
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            var key = reader.ReadTextString();
            var value = Read(reader);
            map[key] = value;

            if (counter++ > MaxIterations)
            {
                throw new InvalidOperationException("Exceeded maximum iterations when reading CBOR map");
            }
        }

        reader.ReadEndMap();
        return map;
    }

    private static List<object> ReadArray(CborReader reader)
    {
        var array = new List<object>();
        reader.ReadStartArray();

        var counter = 0;
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            array.Add(Read(reader));

            if (counter++ > MaxIterations)
            {
                throw new InvalidOperationException("Exceeded maximum iterations when reading CBOR array");
            }
        }

        reader.ReadEndArray();
        return array;
    }
}