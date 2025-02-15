using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// Implementation of the Android Key attestation statement validation strategy.
/// This validates attestation statements according to the FIDO2 specification section 8.4.
/// See: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
/// </summary>
internal class AndroidKeyAttestationStatementStrategy : IAttestationStatementStrategy
{
    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException(
                "Android Key attestation statement cannot be read",
                nameof(attestationObjectData));
        }

        throw new NotImplementedException();
    }
}
