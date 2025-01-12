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
    public void Validate_WhenWindows()
    {
        // Arrange
        var signatureString = "pT9mvKfJZvhVIhiQFI++k4VHwFVFFrrehFVlHWbwuPxwccjgod7GdeaPgoFuEwNXT2GaWCQMdX+wHSuSVyezBKYJiLlVkzZJRkslgSORSVg4BoNCw8wxWag7hhW7qVz81k/Tz+P8gUznAENmTOmDHu6O4sfeSnvT2Z8kN9KMkm1clCDQkGU2bnASYfXBn2/dp2uSNojRH3eyTfNHmt4OfMQYxKJfoywJpHz2m01WuDw7iNwez7Y1dgG6ZhYwd8n6vj6UnEkzm48fRKmdxLErxGRwH4/S8ITGxJAcwxH1MR7esVvVYKp99mle1QCnZKIU4eQlGTRhSAtgryo3qhQVlg==";

        var attestationStatement = new Dictionary<string, object>
        {
            { "alg", (int)PublicKeyAlgorithm.Rs256 },
            { "sig", Convert.FromBase64String(signatureString) },
        };

        var authenticatorDataString = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAGAosBex1EwCtLOvza/Ja7IAIHgppX3fEq9YSztHkiwb17ns0+Px0i+cSd9aTkm1JD5LpAEDAzkBACBZAQCmBcYvuGi9gyjh5lXY0wiL0oYw1voBr5XHTwP+14ezQBR90zV93anRBAfqFr5MLzY+0EB+YhwjvhL51G0INgmFS6rUhpfG1wQp+MvSU7tSaK1MwZKB35r17oU77/zjroBt780iDHGdYaUx4UN0Mi4oIGe9pmZTTiSUOwq9KpoE4aixjVQNfurWUs036xnkFJ5ZMVON4ki8dXLuOtqgtNy06/X98EKsFcwNKA83ob6XKUZCnG2GlWQJyMBnE8p1p4k46r3DF5p6vdVH+3Ibujmcxhw/f6/M6UTvhvYofT+ljqFYhHKT2iRp1m2+iFQJAbcGCvXW9AWVWeqU1tBQ5yENIUMBAAE=";
        var authenticatorDataArray = Convert.FromBase64String(authenticatorDataString);

        // Temporary simplification of tests is to use instance of AuthenticatorDataProvider
        var provider = new AuthenticatorDataProvider();
        var authenticatorData = provider.Get(authenticatorDataArray);

        var attestationObjectData = new AttestationObjectData
        {
            AttestationStatement = attestationStatement,
            AuthenticatorData = authenticatorData,
            AuthenticatorRawData = authenticatorDataArray,
        };

        var clientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ3NqSlRqZzNyY21sM2NmRUx3eEF4USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9";
        var clientData = new ClientData
        {
            ClientDataHash = HashProvider.GetSha256Hash(clientDataJson),
        };

        var creationOptions = new PublicKeyCredentialCreationOptions();

        // Act
        _sut.Validate(attestationObjectData, clientData, creationOptions);
    }
}
