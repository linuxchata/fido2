using System.Formats.Asn1;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Services;

internal sealed class AndroidKeyAttestationExtensionParserService : IAndroidKeyAttestationExtensionParserService
{
    public AndroidKeyAttestation? Parse(byte[] rawData)
    {
        try
        {
            var asnReader = new AsnReader(rawData, AsnEncodingRules.BER);
            var sequence = asnReader.ReadSequence();

            var attestationVersion = (int)sequence!.ReadInteger();
            var attestationSecurityLevel = sequence.ReadEnumeratedValue<AndroidKeySecurityLevel>();
            var keymasterVersion = (int)sequence.ReadInteger();
            var keymasterSecurityLevel = sequence.ReadEnumeratedValue<AndroidKeySecurityLevel>();
            var attestationChallenge = sequence.ReadOctetString();
            var uniqueId = sequence.ReadOctetString();
            var softwareEnforced = sequence.ReadEncodedValue().ToArray();
            var hardwareEnforced = sequence.ReadEncodedValue().ToArray();

            if (sequence.HasData)
            {
                throw new ArgumentException("Android Key attestation extension has extra data");
            }

            if (asnReader.HasData)
            {
                throw new ArgumentException("Android Key attestation extension has extra sequence data");
            }

            return new AndroidKeyAttestation
            {
                AttestationVersion = attestationVersion,
                AttestationSecurityLevel = attestationSecurityLevel,
                KeymasterVersion = keymasterVersion,
                KeymasterSecurityLevel = keymasterSecurityLevel,
                AttestationChallenge = attestationChallenge,
                UniqueId = uniqueId,
                SoftwareEnforced = softwareEnforced,
                HardwareEnforced = hardwareEnforced,
            };
        }
        catch (Exception)
        {
            return null;
        }
    }
}
