using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
public class PackedAttestationStatementStategyTests
{
    private PackedAttestationStatementStategy _sut = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new PackedAttestationStatementStategy();
    }

    [Test]
    public void Validate_()
    {
        // Arrange
        var signatureString = "jFsg1pE0oG+yOUWvf7E/E5aP8DuA9q1fnxk2GZfRn8vQNhqz5Wkx/Zqyevp8RDh+EwjYJIkK3nrLYvTzbnGKMhFSdOJ2N2hacvSO3SsQ890DYTONlVThN6/PpPn4DZ+fEa/yr68vWXm5Lma2GDuJ4gSL08RFPWoerzQtWMNCE4aIv988JJvmIU6BA/uzux3kX9E2Golpn8Vs4XW53U0EsED6TyImTOuCtbSfB8/xkcq2JuhRaJwHQqaV2tIKHnqtvGFDB7yPMxiGi/Skzyv2QitsdlY4DS4jXDH4HrA1VxzIRjBbjfofy0WRAxJtgrEK7a0ZEOEPhaW0vqPR5KZHvQ==";

        var attestationStatement = new Dictionary<string, object>
        {
            { "alg", (int)PublicKeyAlgorithm.Rs256 },
            { "sig", Convert.FromBase64String(signatureString) },
        };

        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIPbZ8TFtu1QIdgyeU/8pErsPUlpyNOO78e5M2fuf6qbapAEDAzkBACBZAQDyo0pfoOrWf6nTz8BLydkpXJwNwU4cdciPBhSrj3oUif0N4MoXDE4cwoBgbtGQ4MVVwKbnn+iTsmi/TJc+G9tIX/LPRyj+0Z2bcMW1TJr1vD3BurP5VV4pd7eeQofWbO0zG7pSn6P/txKRqkCtQu0drUXlfrOek/P1v7rruhAvcXq4JNdVEeajP6OARISK/G62CcpI122cZ/CYH41/4ES0Ik0HgmwtEkRZrQQXAksDWVtf6Cq0xv6nL9CB+b8Stx2jEei5P9mHhP0Kanj0eEUXmjB1kVmwxMSWM0iSc8E9lefS0os9Cue/32eqzf0ybOVaObVb+BUE1kjzrRwmIOjZIUMBAAE=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        _sut.Validate(attestationStatement, authenticatorData!, creationOptions);
    }
}
