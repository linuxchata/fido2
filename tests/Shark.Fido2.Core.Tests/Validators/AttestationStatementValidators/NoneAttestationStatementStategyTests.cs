using Moq;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Handlers;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Core.Validators.AttestationStatementValidators;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Enums;

namespace Shark.Fido2.Core.Tests.Validators.AttestationStatementValidators;

[TestFixture]
public class NoneAttestationStatementStategyTests
{
    private Mock<IAttestationObjectValidator> _attestationObjectValidatorMock;
    private AuthenticatorDataProvider _provider;
    private PublicKeyCredentialCreationOptions _creationOptions;

    private NoneAttestationStatementStategy _sut = null!;

    [SetUp]
    public void Setup()
    {
        _attestationObjectValidatorMock = new Mock<IAttestationObjectValidator>();
        _attestationObjectValidatorMock
            .Setup(a => a.Validate(
                It.IsAny<AttestationObjectData>(),
                It.IsAny<ClientData>(),
                It.IsAny<PublicKeyCredentialCreationOptions>()))
            .Returns(ValidatorInternalResult.Valid());

        _provider = new AuthenticatorDataProvider();

        _creationOptions = new PublicKeyCredentialCreationOptions();

        _sut = new NoneAttestationStatementStategy();
    }

    [Test]
    public void Validate_WheniPhoneAtenticatorWithRs256Algorithm_ShouldValidate()
    {
        // Arrange
        var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFNt4yVHcZrA8zXOCoeW/OoBFGVaEpQECAyYgASFYICclgDbB2uu5zJ9LZkzRVLMWWoR4Q/BYRC7lvqgO8VCtIlggoWadCDIqNEHAe73eeZaRJ3QLv+J1UgNnd96R8r0T6E4=";

        var clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMDRyM1MxbVppeUZUQlpGOFZseWlmQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9";
        var clientData = new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(Convert.FromBase64String(clientDataJson)),
        };

        var handler = new AttestationObjectHandler(_provider, _attestationObjectValidatorMock.Object);

        var internalResult = handler.Handle(attestationObject, clientData, _creationOptions);

        // Act
        var result = _sut.Validate(internalResult.Value!, clientData, _creationOptions);

        // Assert
        var attestationStatementInternalResult = result as AttestationStatementInternalResult;
        Assert.That(attestationStatementInternalResult!.AttestationType, Is.EqualTo(AttestationTypeEnum.None));
    }
}
