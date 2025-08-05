using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// The interface representing the logic to validate JSON Web Signature responses from Android SafetyNet attestation.
/// </summary>
public interface IAndroidSafetyNetJwsResponseValidator
{
    /// <summary>
    /// Pre-validates the Android SafetyNet JWS response.
    /// </summary>
    /// <param name="jwsResponse">The Android SafetyNet JWS response.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult PreValidate(JwsResponse jwsResponse);

    /// <summary>
    /// Validates the Android SafetyNet JWS response.
    /// </summary>
    /// <param name="jwsResponse">The Android SafetyNet JWS response.</param>
    /// <param name="certificate">The X.509 certificate.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(JwsResponse jwsResponse, X509Certificate2 certificate);
}
