# Overview
These server certificates were created to test
- different Relying Party identifiers
- support of multiple origins

According to the [specification](https://www.w3.org/TR/webauthn-2/#rp-id), Relying Party identifiers must comply with the following rule:
```
For example, given a Relying Party whose origin is https://login.example.com:1337, then the following RP IDs are valid: login.example.com (default) and example.com, but not m.login.example.com and not com.
```

# Generate certificates
1. Install `openssl` via Chocolatey.
```choco install openssl```

1. Ensure `openssl` is installed and accessible.
```openssl version```

1. Run `generate_certificates.ps1` to generate new certificates

Password: `secret`

# Use server certificates
1. Update `C:\Windows\System32\drivers\etc\hosts file`:
```
127.0.0.1 example.com
127.0.0.1 login.example.com
127.0.0.1 m.login.example.com
```

1. Add the following logic to `Program.cs`
```
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(443, listenOptions =>
    {
        var certificate = FindCertificateBySubjectName("example.com");
        if (certificate == null)
        {
            throw new Exception("Certificate not found in store");
        }

        var httpsConnectionAdapterOptions = new HttpsConnectionAdapterOptions
        {
            ServerCertificate = certificate,
            SslProtocols = SslProtocols.Tls12,
        };

        listenOptions.UseHttps(httpsConnectionAdapterOptions);
    });
});

static X509Certificate2? FindCertificateBySubjectName(string subjectName)
{
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);

    var certificates = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, validOnly: false);
    return certificates.Count > 0 ? certificates[0] : null;
}
```