using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Results;

public class AttestationStatementInternalResult : ValidatorInternalResult
{
    public AttestationStatementInternalResult(AttestationTypeEnum attestationType)
        : base(true)
    {
        AttestationType = attestationType;
    }

    public AttestationStatementInternalResult(
        AttestationTypeEnum attestationType,
        X509Certificate2[] trustedPath)
        : base(true)
    {
        AttestationType = attestationType;
        TrustedPath = trustedPath;
    }

    public AttestationTypeEnum AttestationType { get; set; }

    public X509Certificate2[]? TrustedPath { get; set; }
}
