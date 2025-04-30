using System.Text.Json;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Mappers;

public static class CredentialMapper
{
    public static CredentialEntity ToEntity(this Credential credential)
    {
        var entity = new CredentialEntity
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
            Transports = string.Join(';', credential.Transports ?? []),
        };

        entity.CredentialPublicKeyJson = JsonSerializer.Serialize(entity.CredentialPublicKey);

        return entity;
    }

    public static Credential? ToDomain(this CredentialEntity? entity)
    {
        if (entity == null)
        {
            return null;
        }

        var credentialPublicKey = entity.CredentialPublicKey ??
            JsonSerializer.Deserialize<CredentialPublicKeyEntity>(entity.CredentialPublicKeyJson);

        return new Credential
        {
            CredentialId = entity.CredentialId,
            UserHandle = entity.UserHandle,
            Username = entity.Username,
            CredentialPublicKey = new CredentialPublicKey
            {
                KeyType = credentialPublicKey!.KeyType,
                Algorithm = credentialPublicKey.Algorithm,
                Modulus = credentialPublicKey.Modulus,
                Exponent = credentialPublicKey.Exponent,
                Curve = credentialPublicKey.Curve,
                XCoordinate = credentialPublicKey.XCoordinate,
                YCoordinate = credentialPublicKey.YCoordinate,
                Key = credentialPublicKey.Key,
            },
            SignCount = entity.SignCount,
            Transports = entity.Transports?.Split(';'),
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
            Transports = entity.Transports?.Split(';'),
        };
    }
}
