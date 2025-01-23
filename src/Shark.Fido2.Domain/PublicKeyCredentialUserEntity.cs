namespace Shark.Fido2.Domain;

public class PublicKeyCredentialUserEntity
{
    public byte[] Id { get; set; } = null!;

    public string Name { get; set; } = null!;

    public string DisplayName { get; set; } = null!;
}
