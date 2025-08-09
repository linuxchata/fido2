using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Abstractions.Services;

/// <summary>
/// The interface representing the logic to read a certificate from a file.
/// </summary>
internal interface ICertificateReaderService
{
    /// <summary>
    /// Reads a certificate from the specified file.
    /// </summary>
    /// <param name="fileName">The file name.</param>
    /// <param name="certificatesDirectory">The certificates directory.</param>
    /// <returns>The X509 certificate.</returns>
    X509Certificate2 Read(string fileName, string certificatesDirectory = "Data/Certificates");
}
