using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.InMemory;

/// <summary>
/// In-memory implementation of the credential repository.
/// </summary>
/// <remarks>
/// This implementation uses in-memory cache as the backing store for FIDO2 credentials.
/// </remarks>
internal sealed class CredentialRepository : ICredentialRepository
{
    private const string CredentialKeyPrefix = "credential";
    private const string UserNameKeyPrefix = "user";

    private static readonly SemaphoreSlim _operationLock = new(1, 1);

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private readonly IDistributedCache _cache;

    private readonly DistributedCacheEntryOptions _options = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24),
    };

    public CredentialRepository(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        var serialized = await _cache.GetStringAsync(GetCredentialKey(credentialId), cancellationToken);
        if (string.IsNullOrWhiteSpace(serialized))
        {
            return null;
        }

        var entity = JsonSerializer.Deserialize<CredentialEntity>(serialized, _jsonOptions);
        return entity.ToDomain();
    }

    public async Task<List<CredentialDescriptor>> Get(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var credentialKey = await _cache.GetStringAsync(GetUserNameKey(username), cancellationToken);
        if (string.IsNullOrWhiteSpace(credentialKey))
        {
            return [];
        }

        var serialized = await _cache.GetStringAsync(credentialKey, cancellationToken);
        if (string.IsNullOrWhiteSpace(serialized))
        {
            return [];
        }

        var entities = JsonSerializer.Deserialize<List<CredentialDescriptorEntity>>(serialized, _jsonOptions) ?? [];
        return entities.Select(e => e.ToLightweightDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return false;
        }

        var serialized = await _cache.GetStringAsync(GetCredentialKey(credentialId), cancellationToken);
        return serialized != null;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.CredentialId);
        ArgumentNullException.ThrowIfNullOrEmpty(credential.UserName);
        ArgumentNullException.ThrowIfNull(credential.UserHandle);
        ArgumentNullException.ThrowIfNull(credential.CredentialPublicKey);

        var entity = credential.ToEntity();

        entity.CreatedAt = DateTime.UtcNow;

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            var credentialKey = GetCredentialKey(entity.CredentialId);
            await SetCredential(credentialKey, entity, cancellationToken);
            await _cache.SetStringAsync(GetUserNameKey(entity.UserName), credentialKey, _options, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var serialized = await _cache.GetStringAsync(GetCredentialKey(credentialId), cancellationToken);
        if (string.IsNullOrWhiteSpace(serialized))
        {
            return;
        }

        var entity = JsonSerializer.Deserialize<CredentialEntity>(serialized!, _jsonOptions);

        entity!.SignCount = signCount;
        entity!.UpdatedAt = DateTime.UtcNow;

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            var credentialKey = GetCredentialKey(entity.CredentialId);
            await SetCredential(credentialKey, entity, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public Task UpdateLastUsedAt(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    private async Task SetCredential(string key, CredentialEntity entity, CancellationToken cancellationToken)
    {
        var serialized = JsonSerializer.Serialize(entity, _jsonOptions);
        await _cache.SetStringAsync(key, serialized, _options, cancellationToken);
    }

    private static string GetCredentialKey(byte[] id)
    {
        return $"{CredentialKeyPrefix}:{Convert.ToBase64String(id)}";
    }

    private static string GetUserNameKey(string username)
    {
        return $"{UserNameKeyPrefix}:{username}";
    }
}
