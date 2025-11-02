using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Tests.Validators;

[TestFixture]
internal class AndroidSafetyNetJwsResponseValidatorTests
{
    private const string ApkPackageName = "com.google.android.gms";
    private const string ApkCertificateDigestSha256 = "digest";
    private const string ApkDigestSha256 = "digest";

    private FakeTimeProvider _timeProvider = null!;
    private X509Certificate2 _certificate = null!;
    private JwsResponse _jwsResponse = null!;

    private AndroidSafetyNetJwsResponseValidator _sut = null!;

    [SetUp]
    public void Setup()
    {
        _timeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _sut = new AndroidSafetyNetJwsResponseValidator(_timeProvider);

        using var rsa = RSA.Create();
        var certificateRequest = new CertificateRequest("CN=attest.android.com, O=Google Inc, L=Mountain View, S=California, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        _jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };
    }

    [TearDown]
    public void TearDown()
    {
        _certificate!.Dispose();
    }

    [Test]
    public void PreValidate_WhenBasicIntegrityIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = null!,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response basicIntegrity is not found"));
    }

    [Test]
    public void PreValidate_WhenCtsProfileMatchIsNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = null!,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response ctsProfileMatch is not found"));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void PreValidate_WhenApkPackageNameIsEmpty_ThenReturnsInvalidResult(string? apkPackageName)
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = apkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response APK information is not found"));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void PreValidate_WhenApkCertificateDigestSha256IsEmpty_ThenReturnsInvalidResult(string? apkCertificateDigestSha256)
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = apkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response APK information is not found"));
    }

    [Test]
    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void PreValidate_WhenApkDigestSha256IsEmpty_ThenReturnsInvalidResult(string? apkDigestSha256)
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = apkDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response APK information is not found"));
    }

    [Test]
    public void PreValidate_WhenCertificatesAreNull_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = null!,
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response certificates are not found"));
    }

    [Test]
    public void PreValidate_WhenCertificatesAreEmpty_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.PreValidate(jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response certificates are not found"));
    }

    [Test]
    public void PreValidate_WhenJwsResponseIsValid_ThenReturnsValidResult()
    {
        // Act
        var result = _sut.PreValidate(_jwsResponse);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WhenJwsResponseIsNull_ThenReturnsInvalidResult()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(null!, _certificate));
    }

    [Test]
    public void Validate_WhenCertificateIsNull_ThenReturnsInvalidResult()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _sut.Validate(_jwsResponse, null!));
    }

    [Test]
    public void Validate_WhenSignatureIsInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var response = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = "invalid",
        };

        // Act
        var result = _sut.Validate(response, _certificate);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response signature is not valid"));
    }

    [Test]
    public void Validate_WhenTimestampIsOld_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().AddMinutes(-5).ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.Validate(jwsResponse, _certificate);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response timestamp is not valid"));
    }

    [Test]
    public void Validate_WhenCtsProfileMatchIsFalse_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = false,
            ApkPackageName = ApkPackageName,
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.Validate(jwsResponse, _certificate);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response ctsProfileMatch is not set to true"));
    }

    [Test]
    public void Validate_WhenPackageNameInvalid_ThenReturnsInvalidResult()
    {
        // Arrange
        var jwsResponse = new JwsResponse
        {
            BasicIntegrity = true,
            CtsProfileMatch = true,
            ApkPackageName = "wrong.package",
            ApkCertificateDigestSha256 = ApkCertificateDigestSha256,
            ApkDigestSha256 = ApkCertificateDigestSha256,
            Certificates = [_certificate],
            TimestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds().ToString(),
            RawToken = GetRawToken(_certificate),
        };

        // Act
        var result = _sut.Validate(jwsResponse, _certificate);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Message, Is.EqualTo("Android SafetyNet attestation statement JWS response package name is not valid"));
    }

    [Test]
    public void Validate_WhenJwsResponseIsValid_ThenReturnsInvalidResult()
    {
        // Act
        var result = _sut.Validate(_jwsResponse, _certificate);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    private static string GetRawToken(X509Certificate2 certificate)
    {
        var signingKey = new X509SecurityKey(certificate);
        var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(
            audience: null,
            issuer: null,
            signingCredentials: signingCredentials);

        return tokenHandler.WriteToken(token);
    }
}
