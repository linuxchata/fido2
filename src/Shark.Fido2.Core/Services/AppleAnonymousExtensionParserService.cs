using System.Formats.Asn1;
using Shark.Fido2.Core.Abstractions.Services;

namespace Shark.Fido2.Core.Services;

internal sealed class AppleAnonymousExtensionParserService : IAppleAnonymousExtensionParserService
{
    private const string Prefix = "Apple Anonymous attestation statement certificate's";

    public byte[]? Parse(byte[] rawData)
    {
        ArgumentNullException.ThrowIfNull(rawData);

        try
        {
            byte[]? nonce = null;

            // https://developer.apple.com/forums/thread/663118
            var reader = new AsnReader(rawData, AsnEncodingRules.BER);
            var mainSequence = reader.ReadSequence();

            var currentTag = mainSequence.PeekTag();
            var octetStringTag = new Asn1Tag(TagClass.ContextSpecific, 1);
            if (currentTag.HasSameClassAndValue(octetStringTag))
            {
                var sequence = mainSequence.ReadSequence(octetStringTag);
                nonce = sequence.ReadOctetString();
                sequence.ThrowIfNotEmpty();
            }

            if (mainSequence.HasData)
            {
                throw new ArgumentException($"{Prefix} extension has extra sequence data");
            }

            if (reader.HasData)
            {
                throw new ArgumentException($"{Prefix} extension has extra data");
            }

            return nonce;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
