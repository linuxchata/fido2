using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to parse subject alternative name extensions.
/// </summary>
public interface ISubjectAlternativeNameParserService
{
    /// <summary>
    /// Parses TPM issuer information from a subject alternative name extension.
    /// </summary>
    /// <param name="subjectAlternativeNameExtension">The X.509 subject alternative name extension.</param>
    /// <returns>The parsed TPM issuer information.</returns>
    TpmIssuer Parse(X509SubjectAlternativeNameExtension subjectAlternativeNameExtension);
}
