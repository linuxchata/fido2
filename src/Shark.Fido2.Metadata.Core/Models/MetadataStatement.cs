using System.Text.Json.Serialization;
using Shark.Fido2.Metadata.Core.Converters;

namespace Shark.Fido2.Metadata.Core.Models;

/// <summary>
/// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys.
/// </summary>
public sealed class MetadataStatement
{
    [JsonPropertyName("legalHeader")]
    public string? LegalHeader { get; set; }

    [JsonPropertyName("aaid")]
    public string? Aaid { get; set; }

    [JsonPropertyName("aaguid")]
    [JsonConverter(typeof(CustomNullableGuidConverter))]
    public Guid? Aaguid { get; set; }

    [JsonPropertyName("attestationCertificateKeyIdentifiers")]
    public string[]? AttestationCertificateKeyIdentifiers { get; set; }

    [JsonPropertyName("description")]
    public required string Description { get; set; }

    [JsonPropertyName("alternativeDescriptions")]
    public IDictionary<string, string>? AlternativeDescriptions { get; set; }

    [JsonPropertyName("authenticatorVersion")]
    public ulong AuthenticatorVersion { get; set; }

    [JsonPropertyName("protocolFamily")]
    public required string ProtocolFamily { get; set; }

    [JsonPropertyName("schema")]
    public ushort Schema { get; set; }

    [JsonPropertyName("upv")]
    public required UnifiedProtocolVersion[] Upv { get; set; }

    [JsonPropertyName("authenticationAlgorithms")]
    public required string[] AuthenticationAlgorithms { get; set; }

    [JsonPropertyName("publicKeyAlgAndEncodings")]
    public required string[] PublicKeyAlgAndEncodings { get; set; }

    [JsonPropertyName("attestationTypes")]
    public required string[] AttestationTypes { get; set; }

    [JsonPropertyName("userVerificationDetails")]
    public required IList<VerificationMethodDescriptor[]> UserVerificationDetails { get; set; }

    [JsonPropertyName("keyProtection")]
    public required string[] KeyProtection { get; set; }

    [JsonPropertyName("isKeyRestricted")]
    public bool? IsKeyRestricted { get; set; }

    [JsonPropertyName("isFreshUserVerificationRequired")]
    public bool? IsFreshUserVerificationRequired { get; set; }

    [JsonPropertyName("matcherProtection")]
    public required string[] MatcherProtection { get; set; }

    [JsonPropertyName("cryptoStrength")]
    public ushort CryptoStrength { get; set; }

    [JsonPropertyName("attachmentHint")]
    public string[]? AttachmentHint { get; set; }

    [JsonPropertyName("tcDisplay")]
    public required string[] TcDisplay { get; set; }

    [JsonPropertyName("tcDisplayContentType")]
    public string? TcDisplayContentType { get; set; }

    [JsonPropertyName("tcDisplayPNGCharacteristics")]
    public DisplayPngCharacteristicsDescriptor[]? TcDisplayPNGCharacteristics { get; set; }

    [JsonPropertyName("attestationRootCertificates")]
    public required string[] AttestationRootCertificates { get; set; }

    [JsonPropertyName("ecdaaTrustAnchors")]
    public EcdaaTrustAnchor[]? EcdaaTrustAnchors { get; set; }

    [JsonPropertyName("icon")]
    public string? Icon { get; set; }

    [JsonPropertyName("supportedExtensions")]
    public ExtensionDescriptor[]? SupportedExtensions { get; set; }

    [JsonPropertyName("authenticatorGetInfo")]
    public IDictionary<string, object>? AuthenticatorGetInfo { get; set; }

    public override string ToString()
    {
        return Description;
    }
}
