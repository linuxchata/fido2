using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Results;

public class AttestationStatementInternalResult : ValidatorInternalResult
{
    public AttestationStatementInternalResult(
        string attestationStatementFormat,
        AttestationTypeEnum attestationType)
        : base(true)
    {
        AttestationStatementFormat = attestationStatementFormat;
        AttestationType = attestationType;
    }

    public AttestationStatementInternalResult(
        string attestationStatementFormat,
        AttestationTypeEnum attestationType,
        X509Certificate2[] trustedPath)
        : base(true)
    {
        AttestationStatementFormat = attestationStatementFormat;
        AttestationType = attestationType;
        TrustPath = trustedPath;
    }

    public string AttestationStatementFormat { get; set; }

    public AttestationTypeEnum AttestationType { get; set; }

    public X509Certificate2[]? TrustPath { get; set; }
}
