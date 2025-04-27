using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.InMemory;

internal sealed class CredentialRepository : ICredentialRepository
{
    private const string CredentialKeyPrefix = "credential";
    private const string UsernameKeyPrefix = "user";

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

    public async Task<Credential?> Get(byte[]? id, CancellationToken cancellationToken = default)
    {
        if (id == null || id.Length == 0)
        {
            return null;
        }

        var serialized = await _cache.GetStringAsync(GetCredentialKey(id), cancellationToken);

        if (!string.IsNullOrWhiteSpace(serialized))
        {
            var entity = JsonSerializer.Deserialize<CredentialEntity>(serialized, _jsonOptions);
            return entity.ToDomain();
        }

        return null;
    }

    public async Task<List<Credential>> Get(string username, CancellationToken cancellationToken = default)
    {
        var entities = await GetInternal(username, cancellationToken);

        return entities.Select(e => e.ToDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? id, CancellationToken cancellationToken = default)
    {
        if (id == null || id.Length == 0)
        {
            return false;
        }

        var serialized = await _cache.GetStringAsync(GetCredentialKey(id), cancellationToken);

        return serialized != null;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var entity = credential.ToEntity();

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            await AddOrUpdateForCredentialId(entity, cancellationToken);
            await AddForUsername(entity, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var entity = credential.ToEntity();

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            await UpdateForCredentialId(entity, signCount, cancellationToken);
            await UpdateForUsername(entity, signCount, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private async Task<List<CredentialEntity>> GetInternal(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var serialized = await _cache.GetStringAsync(GetUsernameKey(username), cancellationToken);

        if (!string.IsNullOrWhiteSpace(serialized))
        {
            return JsonSerializer.Deserialize<List<CredentialEntity>>(serialized, _jsonOptions) ?? [];
        }

        return [];
    }

    private async Task AddOrUpdateForCredentialId(CredentialEntity entity, CancellationToken cancellationToken)
    {
        var serialized = JsonSerializer.Serialize(entity, _jsonOptions);
        await _cache.SetStringAsync(GetCredentialKey(entity.CredentialId), serialized, _options, cancellationToken);
    }

    private async Task AddForUsername(CredentialEntity entity, CancellationToken cancellationToken)
    {
        var entities = await GetInternal(entity.Username, cancellationToken);
        entities.Add(entity);

        var serialized = JsonSerializer.Serialize(entities, _jsonOptions);
        await _cache.SetStringAsync(GetUsernameKey(entity.Username), serialized, _options, cancellationToken);
    }

    private async Task UpdateForCredentialId(CredentialEntity entity, uint signCount, CancellationToken cancellationToken)
    {
        entity.SignCount = signCount;

        await AddOrUpdateForCredentialId(entity, cancellationToken);
    }

    private async Task UpdateForUsername(CredentialEntity entity, uint signCount, CancellationToken cancellationToken)
    {
        var entities = await GetInternal(entity.Username, cancellationToken);

        var targetEntity = entities.FirstOrDefault(c => c.CredentialId.SequenceEqual(entity.CredentialId));
        if (targetEntity != null)
        {
            targetEntity.SignCount = signCount;

            var serialized = JsonSerializer.Serialize(entities, _jsonOptions);
            await _cache.SetStringAsync(GetUsernameKey(entity.Username), serialized, _options, cancellationToken);
        }
    }

    private static string GetCredentialKey(byte[] id)
    {
        return $"{CredentialKeyPrefix}:{Convert.ToBase64String(id)}";
    }

    private static string GetUsernameKey(string username)
    {
        return $"{UsernameKeyPrefix}:{username}";
    }
}
