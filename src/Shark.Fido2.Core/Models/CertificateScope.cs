using System.Security.Cryptography.X509Certificates;

namespace Shark.Fido2.Core.Models;

internal sealed class CertificateScope : IDisposable
{
    private readonly List<X509Certificate2> _certificates = [];
    private bool _disposed = false;
    private bool _released = false;

    public CertificateScope(List<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        _certificates.AddRange(certificates);
    }

    public void Release()
    {
        _released = true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (!_released)
        {
            foreach (var certificate in _certificates)
            {
                certificate.Dispose();
            }
        }
    }
}
