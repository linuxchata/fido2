using System.Formats.Asn1;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Services;

/// <summary>
/// Key and ID attestation parser
/// https://source.android.com/docs/security/features/keystore/attestation.
/// </summary>
internal sealed class AndroidKeyAttestationExtensionParserService : IAndroidKeyAttestationExtensionParserService
{
    private const string Prefix = "Android Key attestation statement certificate's";

    public AndroidKeyAttestation? Parse(byte[] rawData)
    {
        ArgumentNullException.ThrowIfNull(rawData);

        try
        {
            var reader = new AsnReader(rawData, AsnEncodingRules.BER);
            var sequence = reader.ReadSequence();

            var attestationVersion = (int)sequence!.ReadInteger();
            var attestationSecurityLevel = sequence.ReadEnumeratedValue<AndroidKeySecurityLevel>();
            var keymasterVersion = (int)sequence.ReadInteger();
            var keymasterSecurityLevel = sequence.ReadEnumeratedValue<AndroidKeySecurityLevel>();
            var attestationChallenge = sequence.ReadOctetString();
            var uniqueId = sequence.ReadOctetString();
            var softwareEnforced = sequence.ReadEncodedValue().ToArray();
            var hardwareEnforced = sequence.ReadEncodedValue().ToArray();

            var softwareEnforcedAuthorizationList = ReadAuthorizationList(softwareEnforced, "software");
            var hardwareEnforcedAuthorizationList = ReadAuthorizationList(hardwareEnforced, "hardware (TEE)");

            if (sequence.HasData)
            {
                throw new ArgumentException($"{Prefix} extension has extra sequence data");
            }

            if (reader.HasData)
            {
                throw new ArgumentException($"{Prefix} extension has extra data");
            }

            return new AndroidKeyAttestation
            {
                AttestationVersion = attestationVersion,
                AttestationSecurityLevel = attestationSecurityLevel,
                KeymasterVersion = keymasterVersion,
                KeymasterSecurityLevel = keymasterSecurityLevel,
                AttestationChallenge = attestationChallenge,
                UniqueId = uniqueId,
                SoftwareEnforced = softwareEnforcedAuthorizationList,
                HardwareEnforced = hardwareEnforcedAuthorizationList,
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static AndroidKeyAuthorizationList ReadAuthorizationList(byte[] authorizationList, string authListType)
    {
        var authorizationListReader = new AsnReader(authorizationList, AsnEncodingRules.BER);
        var authorizationListSequence = authorizationListReader.ReadSequence();

        var purposeTag = new Asn1Tag(TagClass.ContextSpecific, 1);
        var allApplicationsTag = new Asn1Tag(TagClass.ContextSpecific, 600);
        var originTag = new Asn1Tag(TagClass.ContextSpecific, 702);

        var purpose = 0;
        var isAllApplicationsPresent = false;
        var origin = 0;

        Asn1Tag currentTag;
        while (authorizationListSequence.HasData)
        {
            currentTag = authorizationListSequence.PeekTag();

            if (currentTag.HasSameClassAndValue(purposeTag))
            {
                var sequence = authorizationListSequence.ReadSequence(purposeTag);
                var purposeSetReader = sequence.ReadSetOf();
                purpose = (int)purposeSetReader.ReadInteger();
                sequence.ThrowIfNotEmpty();
            }
            else if (currentTag.HasSameClassAndValue(allApplicationsTag))
            {
                authorizationListSequence.ReadNull();
                isAllApplicationsPresent = true;
            }
            else if (currentTag.HasSameClassAndValue(originTag))
            {
                var sequence = authorizationListSequence.ReadSequence(originTag);
                origin = (int)sequence.ReadInteger();
                sequence.ThrowIfNotEmpty();
            }
            else
            {
                authorizationListSequence.ReadEncodedValue();
            }
        }

        if (authorizationListReader.HasData)
        {
            throw new ArgumentException($"{Prefix} {authListType} authorization list has extra data");
        }

        return new AndroidKeyAuthorizationList
        {
            Purpose = purpose,
            IsAllApplicationsPresent = isAllApplicationsPresent,
            Origin = origin,
        };
    }
}
