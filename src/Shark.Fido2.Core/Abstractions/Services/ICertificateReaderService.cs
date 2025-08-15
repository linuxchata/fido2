using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to read a certificate from an embedded resource.
/// </summary>
internal interface ICertificateReaderService
{
    /// <summary>
    /// Reads a certificate from the specified embedded resource located in 'Data/Certificates' directory.
    /// </summary>
    /// <param name="embeddedCertificateName">The embedded certificate name.</param>
    /// <returns>The X509 certificate.</returns>
    X509Certificate2 Read(string embeddedCertificateName);
}
