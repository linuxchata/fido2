using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators;

public interface ICertificateAttestationStatementValidator
{
    bool IsCertificatePresent(Dictionary<string, object> attestationStatementDict);

    ValidatorInternalResult Validate(
        Dictionary<string, object> attestationStatementDict,
        AttestationObjectData attestationObjectData);
}
