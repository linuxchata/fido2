namespace Shark.Fido2.Core.Entities;

public sealed class CredentialPublicKeyEntity
{
    public int KeyType { get; set; }

    public int Algorithm { get; set; }

    public byte[]? Modulus { get; set; }

    public byte[]? Exponent { get; set; }

    public int? Curve { get; set; }

    public byte[]? XCoordinate { get; set; }

    public byte[]? YCoordinate { get; set; }

    public byte[]? Key { get; set; }
}
