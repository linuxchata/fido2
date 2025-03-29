using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;

/// <summary>
/// Validates the JWS (JSON Web Signature) response from Android SafetyNet attestation.
/// This validator ensures the authenticity and integrity of the SafetyNet response
/// by validating its signature, timestamp, and package name.
/// </summary>
public interface IAndroidSafetyNetJwsResponseValidator
{
    /// <summary>
    /// Pre-validates the Android SafetyNet JWS response.
    /// </summary>
    /// <param name="jwsResponse">The JWS response from Android SafetyNet containing attestation data.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult PreValidate(JwsResponse jwsResponse);

    /// <summary>
    /// Validates the Android SafetyNet JWS response.
    /// </summary>
    /// <param name="jwsResponse">The JWS response from Android SafetyNet containing attestation data.</param>
    /// <param name="certificate">The X.509 certificate used to validate the JWS signature.</param>
    /// <returns>A validation result indicating success or failure with error details.</returns>
    ValidatorInternalResult Validate(JwsResponse jwsResponse, X509Certificate2 certificate);
}
