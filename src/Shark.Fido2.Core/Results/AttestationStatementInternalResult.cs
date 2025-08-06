using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Results;

public class AttestationStatementInternalResult : ValidatorInternalResult
{
    public AttestationStatementInternalResult(
        string attestationStatementFormat,
        AttestationType attestationType)
        : base(true)
    {
        AttestationStatementFormat = attestationStatementFormat;
        AttestationType = attestationType;
    }

    public AttestationStatementInternalResult(
        string attestationStatementFormat,
        AttestationType attestationType,
        X509Certificate2[] trustedPath)
        : base(true)
    {
        AttestationStatementFormat = attestationStatementFormat;
        AttestationType = attestationType;
        TrustPath = trustedPath;
    }

    public string AttestationStatementFormat { get; }

    public AttestationType AttestationType { get; }

    public X509Certificate2[]? TrustPath { get; }
}
