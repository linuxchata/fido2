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
    private readonly TimeProvider _timeProvider;

    private readonly DistributedCacheEntryOptions _options = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24),
    };

    public CredentialRepository(IDistributedCache cache, TimeProvider timeProvider)
    {
        _cache = cache;
        _timeProvider = timeProvider;
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        var serializedCredential = await GetCredential(credentialId, cancellationToken);
        if (string.IsNullOrWhiteSpace(serializedCredential))
        {
            return null;
        }

        var entity = JsonSerializer.Deserialize<CredentialEntity>(serializedCredential, _jsonOptions);
        return entity.ToDomain();
    }

    public async Task<List<CredentialDescriptor>> Get(string userName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            return [];
        }

        var serializedCredentialsKeys = await _cache.GetStringAsync(GetUserNameKey(userName), cancellationToken);
        if (string.IsNullOrWhiteSpace(serializedCredentialsKeys))
        {
            return [];
        }

        var entities = new List<CredentialDescriptorEntity>();

        var credentialsKeys = JsonSerializer.Deserialize<List<string>>(serializedCredentialsKeys!, _jsonOptions) ?? [];

        foreach (var credentialKey in credentialsKeys)
        {
            if (string.IsNullOrWhiteSpace(credentialKey))
            {
                continue;
            }

            var serializedCredential = await _cache.GetStringAsync(credentialKey, cancellationToken);
            if (string.IsNullOrWhiteSpace(serializedCredential))
            {
                continue;
            }

            var entity = JsonSerializer.Deserialize<CredentialDescriptorEntity>(serializedCredential, _jsonOptions);
            if (entity != null)
            {
                entities.Add(entity);
            }
        }

        return entities.Select(e => e.ToLightweightDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return false;
        }

        var serializedCredential = await GetCredential(credentialId, cancellationToken);
        return serializedCredential != null;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.CredentialId);
        ArgumentNullException.ThrowIfNullOrEmpty(credential.UserName);
        ArgumentNullException.ThrowIfNull(credential.UserHandle);
        ArgumentNullException.ThrowIfNull(credential.CredentialPublicKey);

        var entity = credential.ToEntity();

        entity.CreatedAt = GetUtcDateTime();

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            var credentialKey = GetCredentialKey(entity.CredentialId);
            await SetCredential(credentialKey, entity, cancellationToken);
            await SetUserName(entity.UserName, credentialKey, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default)
    {
        await UpdateCredential(
            credentialId,
            entity =>
            {
                var now = GetUtcDateTime();
                entity.SignCount = signCount;
                entity.UpdatedAt = now;
                entity.LastUsedAt = now;
            },
            cancellationToken);
    }

    public async Task UpdateLastUsedAt(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        await UpdateCredential(
            credentialId,
            entity =>
            {
                entity.LastUsedAt = GetUtcDateTime();
            },
            cancellationToken);
    }

    private static string GetCredentialKey(byte[] id)
    {
        return $"{CredentialKeyPrefix}:{Convert.ToBase64String(id)}";
    }

    private static string GetUserNameKey(string username)
    {
        return $"{UserNameKeyPrefix}:{username}";
    }

    private Task<string?> GetCredential(byte[] credentialId, CancellationToken cancellationToken)
    {
        return _cache.GetStringAsync(GetCredentialKey(credentialId), cancellationToken);
    }

    private async Task SetCredential(string key, CredentialEntity entity, CancellationToken cancellationToken)
    {
        var serializedCredential = JsonSerializer.Serialize(entity, _jsonOptions);
        await _cache.SetStringAsync(key, serializedCredential, _options, cancellationToken);
    }

    private async Task SetUserName(string userName, string credentialKey, CancellationToken cancellationToken)
    {
        var userNameKey = GetUserNameKey(userName);

        List<string> credentialsKeys;

        var serializedCredentialsKeys = await _cache.GetStringAsync(userNameKey, cancellationToken);
        if (string.IsNullOrEmpty(serializedCredentialsKeys))
        {
            credentialsKeys = [credentialKey];
        }
        else
        {
            credentialsKeys = JsonSerializer.Deserialize<List<string>>(serializedCredentialsKeys!, _jsonOptions) ?? [];
            if (!credentialsKeys.Exists(ck => ck == credentialKey))
            {
                credentialsKeys.Add(credentialKey);
            }
        }

        serializedCredentialsKeys = JsonSerializer.Serialize(credentialsKeys, _jsonOptions);
        await _cache.SetStringAsync(userNameKey, serializedCredentialsKeys, _options, cancellationToken);
    }

    private async Task UpdateCredential(
        byte[] credentialId,
        Action<CredentialEntity> updateCredentialEntity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        var serializedCredential = await GetCredential(credentialId, cancellationToken);
        if (string.IsNullOrWhiteSpace(serializedCredential))
        {
            return;
        }

        var entity = JsonSerializer.Deserialize<CredentialEntity>(serializedCredential, _jsonOptions);
        if (entity == null)
        {
            return;
        }

        updateCredentialEntity(entity);

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            await SetCredential(GetCredentialKey(entity.CredentialId), entity, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private DateTime GetUtcDateTime()
    {
        return _timeProvider.GetUtcNow().UtcDateTime;
    }
}
