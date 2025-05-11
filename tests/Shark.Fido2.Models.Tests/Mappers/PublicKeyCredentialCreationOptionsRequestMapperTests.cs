using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Domain.Constants;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Models.Mappers;
using Shark.Fido2.Models.Requests;

namespace Shark.Fido2.Models.Tests.Mappers;

[TestFixture]
public class PublicKeyCredentialCreationOptionsRequestMapperTests
{
    [Test]
    public void MapCreationOptions_WhenServerRequestIsValid_ThenReturnsPublicKeyCredentialCreationOptionsRequest()
    {
        // Arrange
        var serverRequest = new ServerPublicKeyCredentialCreationOptionsRequest
        {
            Username = "Username",
            DisplayName = "DisplayName",
            AuthenticatorSelection = new ServerAuthenticatorSelectionCriteriaRequest
            {
                AuthenticatorAttachment = AuthenticatorAttachment.Platform.GetValue(),
                ResidentKey = ResidentKeyRequirement.Required.GetValue(),
                RequireResidentKey = true,
                UserVerification = UserVerificationRequirement.Required.GetValue(),
            },
            Attestation = AttestationConveyancePreference.Direct,
        };

        // Act
        var result = serverRequest.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserName, Is.EqualTo(serverRequest.Username));
        Assert.That(result.DisplayName, Is.EqualTo(serverRequest.DisplayName));
        Assert.That(result.Attestation, Is.EqualTo(serverRequest.Attestation));
        Assert.That(result.AuthenticatorSelection, Is.Not.Null);
        Assert.That(result.AuthenticatorSelection.AuthenticatorAttachment, Is.EqualTo(AuthenticatorAttachment.Platform));
        Assert.That(result.AuthenticatorSelection.ResidentKey, Is.EqualTo(ResidentKeyRequirement.Required));
        Assert.That(result.AuthenticatorSelection.RequireResidentKey, Is.True);
        Assert.That(result.AuthenticatorSelection.UserVerification, Is.EqualTo(UserVerificationRequirement.Required));
    }

    [Test]
    public void MapCreationOptions_WhenAuthenticatorSelectionIsNull_ThenReturnsPublicKeyCredentialCreationOptionsRequest()
    {
        // Arrange
        var serverRequest = new ServerPublicKeyCredentialCreationOptionsRequest
        {
            Username = "Username",
            DisplayName = "DisplayName",
            AuthenticatorSelection = null,
            Attestation = AttestationConveyancePreference.None,
        };

        // Act
        var result = serverRequest.Map();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.UserName, Is.EqualTo(serverRequest.Username));
        Assert.That(result.DisplayName, Is.EqualTo(serverRequest.DisplayName));
        Assert.That(result.Attestation, Is.EqualTo(serverRequest.Attestation));
        Assert.That(result.AuthenticatorSelection, Is.Null);
    }
}
