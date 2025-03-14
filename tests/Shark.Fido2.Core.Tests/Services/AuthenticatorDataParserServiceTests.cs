using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Services;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class AuthenticatorDataParserServiceTests
{
    private AuthenticatorDataParserService _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new AuthenticatorDataParserService();
    }

    [Test]
    public void Parse_WhenAttestedCredentialDataIncludedAndEc2KeyType_ThenReturnsAuthenticatorData()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNIOIaOVgJRyI6ffE8tNV4tHvGJVpQECAyYgASFYIEgIOe/+LSvpyPB010CZ4+ox3EAG6dp611nzoff5QH15IlggC/DWA8k1rogu86PSgVzEjD9ObamYaO2dbj710ogx1dw=";
        var authenticatorData = authenticatorDataString.FromBase64Url();

        // Act
        var result = _sut.Parse(authenticatorData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }

    [Test]
    public void Parse_WhenAttestedCredentialDataIncludedAndRsaKeyType_ThenReturnsAuthenticatorData()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIPbZ8TFtu1QIdgyeU/8pErsPUlpyNOO78e5M2fuf6qbapAEDAzkBACBZAQDyo0pfoOrWf6nTz8BLydkpXJwNwU4cdciPBhSrj3oUif0N4MoXDE4cwoBgbtGQ4MVVwKbnn+iTsmi/TJc+G9tIX/LPRyj+0Z2bcMW1TJr1vD3BurP5VV4pd7eeQofWbO0zG7pSn6P/txKRqkCtQu0drUXlfrOek/P1v7rruhAvcXq4JNdVEeajP6OARISK/G62CcpI122cZ/CYH41/4ES0Ik0HgmwtEkRZrQQXAksDWVtf6Cq0xv6nL9CB+b8Stx2jEei5P9mHhP0Kanj0eEUXmjB1kVmwxMSWM0iSc8E9lefS0os9Cue/32eqzf0ybOVaObVb+BUE1kjzrRwmIOjZIUMBAAE=";
        var authenticatorData = authenticatorDataString.FromBase64Url();

        // Act
        var result = _sut.Parse(authenticatorData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }

    [Test]
    public void Parse_WhenAttestedCredentialDataNotIncluded_ThenReturnsAuthenticatorData()
    {
        // Arrange
        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2OBAAAAK6A";
        var authenticatorData = authenticatorDataString.FromBase64Url();

        // Act
        var result = _sut.Parse(authenticatorData);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.AttestedCredentialData, Is.Not.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Not.Null);
    }

    [Test]
    [Ignore("Enable when reading of extension data is implemented")]
    public void Parse_WhenAuthenticatorDataHasLeftOverBytes_ThenReturnsAuthenticatorData()
    {
        // Arrange
        var authenticatorDataString = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAI0LSBwDHje1bHYttXRWm558o40Q6AvCFl8vm5W4JqX8AiA1qNgsfkIRgX-db7oLvpZH1R4M21B4grW0TpPjJ9L2WmN4NWOBWQRFMIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAALzJq3PAM70bQk5KY1sSoSnIAIHmOMqiMsUSfuiiYolMxyxXLTV-bagf1IkFuFskq6BvRpQECAyYgASFYINHhlAO9D0gAUC6qWiLUDJ39rp6RKn0CXyiIOBRUpoYHIlggNWv5YiUYXJCdnUpAICOa5BeX5992RAHl9AvbE0--wZmgYIlbSSaOgHItKQL6ZnvRV576WVWRxflB77cP6DcEskk";
        var authenticatorData = authenticatorDataString.FromBase64Url();

        // Act
        var result = _sut.Parse(authenticatorData);

        // Assert
        Assert.That(result, Is.Null);
        Assert.That(result!.AttestedCredentialData, Is.Null);
        Assert.That(result.AttestedCredentialData.CredentialPublicKey, Is.Null);
    }
}