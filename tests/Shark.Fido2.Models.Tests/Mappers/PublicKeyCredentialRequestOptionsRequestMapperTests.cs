﻿using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
public class PublicKeyCredentialRequestOptionsRequestMapperTests
{
    [Test]
    public void Map_WhenRequestIsValid_ThenReturnsPublicKeyCredentialRequestOptionsRequest()
    {
        // Arrange
        var request = new ServerPublicKeyCredentialGetOptionsRequest
        {
            Username = "Username",
            UserVerification = UserVerificationRequirement.Required.GetValue(),
        };

        // Act
        var result = request.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserName, Is.EqualTo(request.Username));
        Assert.That(result.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
    }

    [Test]
    public void Map_WhenUserVerificationIsNull_ThenReturnsPublicKeyCredentialRequestOptionsRequest()
    {
        // Arrange
        var request = new ServerPublicKeyCredentialGetOptionsRequest
        {
            Username = "Username",
            UserVerification = null,
        };

        // Act
        var result = request.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserName, Is.EqualTo(request.Username));
        Assert.That(result.UserVerification, Is.Null);
    }
}
