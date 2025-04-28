using Shark.Fido2.Core.Entities;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Mappers;

public static class CredentialMapper
{
    public static CredentialEntity ToEntity(this Credential credential)
    {
        return new CredentialEntity
        {
            CredentialId = credential.CredentialId,
            UserHandle = credential.UserHandle,
            Username = credential.Username,
            CredentialPublicKey = new CredentialPublicKeyEntity
            {
                KeyType = credential.CredentialPublicKey.KeyType,
                Algorithm = credential.CredentialPublicKey.Algorithm,
                Modulus = credential.CredentialPublicKey.Modulus,
                Exponent = credential.CredentialPublicKey.Exponent,
                Curve = credential.CredentialPublicKey.Curve,
                XCoordinate = credential.CredentialPublicKey.XCoordinate,
                YCoordinate = credential.CredentialPublicKey.YCoordinate,
                Key = credential.CredentialPublicKey.Key,
            },
            SignCount = credential.SignCount,
            Transports = credential.Transports,
        };
    }

    public static Credential? ToDomain(this CredentialEntity? entity)
    {
        if (entity == null)
        {
            return null;
        }

        return new Credential
        {
            CredentialId = entity.CredentialId,
            UserHandle = entity.UserHandle,
            Username = entity.Username,
            CredentialPublicKey = new CredentialPublicKey
            {
                KeyType = entity.CredentialPublicKey.KeyType,
                Algorithm = entity.CredentialPublicKey.Algorithm,
                Modulus = entity.CredentialPublicKey.Modulus,
                Exponent = entity.CredentialPublicKey.Exponent,
                Curve = entity.CredentialPublicKey.Curve,
                XCoordinate = entity.CredentialPublicKey.XCoordinate,
                YCoordinate = entity.CredentialPublicKey.YCoordinate,
                Key = entity.CredentialPublicKey.Key,
            },
            SignCount = entity.SignCount,
            Transports = entity.Transports,
        };
    }

    public static CredentialDescriptor? ToLightweightDomain(this CredentialEntity? entity)
    {
        if (entity == null)
        {
            return null;
        }

        return new CredentialDescriptor
        {
            CredentialId = entity.CredentialId,
            Transports = entity.Transports,
        };
    }
}
