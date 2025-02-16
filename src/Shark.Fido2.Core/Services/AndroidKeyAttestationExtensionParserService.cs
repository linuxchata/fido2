using System.Formats.Asn1;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Services;

/// <summary>
/// Key and ID attestation parser
/// https://source.android.com/docs/security/features/keystore/attestation
/// </summary>
internal sealed class AndroidKeyAttestationExtensionParserService : IAndroidKeyAttestationExtensionParserService
{
    public AndroidKeyAttestation? Parse(byte[] rawData)
    {
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

            var softwareEnforcedAuthorizationList = ReadAuthorizationList(softwareEnforced);
            var hardwareEnforcedAuthorizationList = ReadAuthorizationList(hardwareEnforced);

            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

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

    private static AndroidKeyAuthorizationList ReadAuthorizationList(byte[] authorizationList)
    {
        var authorizationListReader = new AsnReader(authorizationList, AsnEncodingRules.BER);
        var authorizationListSequence = authorizationListReader.ReadSequence();

        var purposeTag = new Asn1Tag(TagClass.ContextSpecific, 1);
        var allApplicationsTag = new Asn1Tag(TagClass.ContextSpecific, 600);
        var originTag = new Asn1Tag(TagClass.ContextSpecific, 702);

        var purpose = 0;
        var isAllApplicationsPresent = false;
        var origin = 0;

        while (authorizationListSequence.HasData)
        {
            if (authorizationListSequence.PeekTag().HasSameClassAndValue(purposeTag))
            {
                var sequence = authorizationListSequence.ReadSequence(purposeTag);
                var purposeSetReader = sequence.ReadSetOf();
                purpose = (int)purposeSetReader.ReadInteger();
                sequence.ThrowIfNotEmpty();
            }
            else if (authorizationListSequence.PeekTag().HasSameClassAndValue(allApplicationsTag))
            {
                isAllApplicationsPresent = true;
            }
            else if (authorizationListSequence.PeekTag().HasSameClassAndValue(originTag))
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

        authorizationListSequence.ThrowIfNotEmpty();

        return new AndroidKeyAuthorizationList
        {
            Purpose = purpose,
            IsAllApplicationsPresent = isAllApplicationsPresent,
            Origin = origin,
        };
    }
}
