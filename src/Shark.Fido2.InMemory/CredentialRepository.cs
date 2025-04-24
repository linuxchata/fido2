using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
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
            return JsonSerializer.Deserialize<Credential>(serialized, _jsonOptions);
        }

        return null;
    }

    public async Task<List<Credential>> Get(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var serialized = await _cache.GetStringAsync(GetUsernameKey(username), cancellationToken);

        if (!string.IsNullOrWhiteSpace(serialized))
        {
            return JsonSerializer.Deserialize<List<Credential>>(serialized, _jsonOptions) ?? [];
        }

        return [];
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            await AddOrUpdateForCredentialId(credential, cancellationToken);
            await AddForUsername(credential, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _operationLock.WaitAsync(cancellationToken);

        try
        {
            await UpdateForCredentialId(credential, signCount, cancellationToken);
            await UpdateForUsername(credential, signCount, cancellationToken);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private async Task AddOrUpdateForCredentialId(Credential credential, CancellationToken cancellationToken)
    {
        var serialized = JsonSerializer.Serialize(credential, _jsonOptions);
        await _cache.SetStringAsync(GetCredentialKey(credential.CredentialId), serialized, _options, cancellationToken);
    }

    private async Task AddForUsername(Credential credential, CancellationToken cancellationToken)
    {
        var credentials = await Get(credential.Username, cancellationToken);
        credentials.Add(credential);

        var serialized = JsonSerializer.Serialize(credentials, _jsonOptions);
        await _cache.SetStringAsync(GetUsernameKey(credential.Username), serialized, _options, cancellationToken);
    }

    private async Task UpdateForCredentialId(Credential credential, uint signCount, CancellationToken cancellationToken)
    {
        credential.SignCount = signCount;

        await AddOrUpdateForCredentialId(credential, cancellationToken);
    }

    private async Task UpdateForUsername(Credential credential, uint signCount, CancellationToken cancellationToken)
    {
        var credentials = await Get(credential.Username, cancellationToken);

        var targetCredential = credentials.FirstOrDefault(c => c.CredentialId.SequenceEqual(credential.CredentialId));
        if (targetCredential != null)
        {
            targetCredential!.SignCount = signCount;

            var serialized = JsonSerializer.Serialize(credentials, _jsonOptions);
            await _cache.SetStringAsync(GetUsernameKey(credential.Username), serialized, _options, cancellationToken);
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
