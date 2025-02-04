using System.Security.Cryptography.X509Certificates;
using Shark.Fido2.Domain.Tpm;

namespace Shark.Fido2.Core.Abstractions.Services;

public interface ISubjectAlternativeNameParserService
{
    TpmIssuer Parse(X509SubjectAlternativeNameExtension subjectAlternativeNameExtension);
}
