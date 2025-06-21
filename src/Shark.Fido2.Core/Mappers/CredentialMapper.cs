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
            UserName = credential.UserName,
            UserDisplayName = credential.UserDisplayName,
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
            CreatedAt = credential.CreatedAt,
            UpdatedAt = credential.UpdatedAt,
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
            UserName = entity.UserName,
            UserDisplayName = entity.UserDisplayName,
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
            Transports = MapTransports(entity.Transports),
            CreatedAt = entity.CreatedAt,
            UpdatedAt = entity.UpdatedAt,
        };
    }

    public static CredentialDescriptor? ToLightweightDomain(this CredentialDescriptorEntity? entity)
    {
        if (entity == null)
        {
            return null;
        }

        return new CredentialDescriptor
        {
            CredentialId = entity.CredentialId,
            Transports = MapTransports(entity.Transports),
        };
    }

    private static string[]? MapTransports(string? transports)
    {
        if (string.IsNullOrWhiteSpace(transports))
        {
            return [];
        }

        return transports?.Split(';');
    }
}
