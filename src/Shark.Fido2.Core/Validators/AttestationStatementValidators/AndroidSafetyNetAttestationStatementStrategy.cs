using System.Text;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Constants;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators;

/// <summary>
/// 8.5. Android SafetyNet Attestation Statement Format
/// </summary>
internal class AndroidSafetyNetAttestationStatementStrategy : IAttestationStatementStrategy
{
    private readonly ICertificateAttestationStatementService _certificateProvider;

    public AndroidSafetyNetAttestationStatementStrategy(
        ICertificateAttestationStatementService certificateAttestationStatementProvider)
    {
        _certificateProvider = certificateAttestationStatementProvider;
    }

    public ValidatorInternalResult Validate(AttestationObjectData attestationObjectData, ClientData clientData)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectData);
        ArgumentNullException.ThrowIfNull(attestationObjectData.AttestationStatement);
        ArgumentNullException.ThrowIfNull(clientData);

        if (attestationObjectData.AttestationStatement is not Dictionary<string, object> attestationStatementDict)
        {
            throw new ArgumentException("Attestation statement cannot be read", nameof(attestationObjectData));
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Version, out var version) ||
            version is not string)
        {
            return ValidatorInternalResult.Invalid("Attestation statement ver cannot be read");
        }

        if (!attestationStatementDict.TryGetValue(AttestationStatement.Response, out var response) ||
            response is not byte[])
        {
            return ValidatorInternalResult.Invalid("Attestation statement response cannot be read");
        }

        var jwsResponse = Encoding.UTF8.GetString((byte[])response);

        var concatenatedData = BytesArrayHelper.Concatenate(
            attestationObjectData.AuthenticatorRawData,
            clientData.ClientDataHash);

        var certificates = _certificateProvider.GetCertificates(attestationStatementDict);

        return new AttestationStatementInternalResult(AttestationTypeEnum.Basic, [.. certificates]);
    }
}
