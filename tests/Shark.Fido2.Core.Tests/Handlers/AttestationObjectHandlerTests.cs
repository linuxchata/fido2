using Moq;
using Shark.Fido2.Core.Abstractions.Services;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Services;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Options;

namespace Shark.Fido2.Core.Tests.Handlers;

[TestFixture]
internal class AttestationObjectHandlerTests
{
    private AttestationObjectHandler _sut = null!;
    private IAuthenticatorDataParserService _authenticatorDataParserService = null!;
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock = null!;

    [SetUp]
    public void Setup()
    {
        _authenticatorDataParserService = new AuthenticatorDataParserService();

        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();
        _attestationObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AttestationObjectData?>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidatorInternalResult.Valid());

        _sut = new AttestationObjectHandler(
            _authenticatorDataParserService,
            _attestationObjectValidatorMock.Object);
    }

    [Test]
    public async Task Handle_WheniPhone8AttestationObjectValid_ThenReturnsValue()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Handle(
            attestationObject, ClientDataBuilder.BuildCreate(), creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public async Task Handle_WheniPhone14AttestationObjectValid_ThenReturnsValue()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFMM5L/63IyA9jqYyiZ9EaOwWhG40pQECAyYgASFYIHFhbupdvz+UhnJF4mph/jreh1RzjE7NDyl54kPLlbiLIlggdqxWZTTqfjbFSXBmGW0RWEJfvljHTKfB9upz0SBkPj8=";
        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Handle(
            attestationObject, ClientDataBuilder.BuildCreate(), creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public async Task Handle_WhenWindowsAttestationObjectValid_ThenReturnsValue()
    {
        // Arrange
        var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQClP2a8p8lm+FUiGJAUj76ThUfAVUUWut6EVWUdZvC4/HBxyOCh3sZ15o+CgW4TA1dPYZpYJAx1f7AdK5JXJ7MEpgmIuVWTNklGSyWBI5FJWDgGg0LDzDFZqDuGFbupXPzWT9PP4/yBTOcAQ2ZM6YMe7o7ix95Ke9PZnyQ30oySbVyUINCQZTZucBJh9cGfb92na5I2iNEfd7JN80ea3g58xBjEol+jLAmkfPabTVa4PDuI3B7PtjV2AbpmFjB3yfq+PpScSTObjx9EqZ3EsSvEZHAfj9LwhMbEkBzDEfUxHt6xW9Vgqn32aV7VAKdkohTh5CUZNGFIC2CvKjeqFBWWaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";
        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act
        var result = await _sut.Handle(
            attestationObject, ClientDataBuilder.BuildCreate(), creationOptions, CancellationToken.None);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Message, Is.Null);
        Assert.That(result.Value, Is.Not.Null);
    }

    [Test]
    public void Handle_WhenAttestationObjectHasLeftoversBytes_ThenThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgB_JH2L3z11Eszp0n_Kz_hz9-_zONjxp7gNxAq6rNOPcCIQCgUxEuaWW8Q0nihL5mPNMGEfCsvFl5ZJ8Pw8l3Rlq0TWN4NWOBWQRFMIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAdDJq3PAM70bQk5KY1sSoSnIAIJsR0dMx7XHR5cpOgVaue6iSYUvhkRBTx7w-HaE7eoIOpQECAyYgASFYIL7nxBFER7y8BC2dHlGZyRTNEJSdNQZbK1cEiy9ovcpGIlggagrT30zq5uvWuLSHAt6TaqMB-WsW1IYYge0RoxhE9GHBzkNHCH5a87ywmMl_zniBVKDOCT4_g5yHyM3FcsC3jg";
        var creationOptions = PublicKeyCredentialCreationOptionsBuilder.Build();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _sut.Handle(
            attestationObject,
            ClientDataBuilder.BuildCreate(),
            creationOptions,
            CancellationToken.None));
    }
}