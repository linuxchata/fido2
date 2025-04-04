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

    public CredentialRepository(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task<Credential?> Get(byte[]? id)
    {
        if (id == null || id.Length == 0)
        {
            return null;
        }

        var serialized = await _cache.GetStringAsync(GetCredentialKey(id));

        if (!string.IsNullOrWhiteSpace(serialized))
        {
            return JsonSerializer.Deserialize<Credential>(serialized, _jsonOptions);
        }

        return null;
    }

    public async Task<List<Credential>> Get(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var serialized = await _cache.GetStringAsync(GetUsernameKey(username));

        if (!string.IsNullOrWhiteSpace(serialized))
        {
            return JsonSerializer.Deserialize<List<Credential>>(serialized, _jsonOptions) ?? [];
        }

        return [];
    }

    public async Task Add(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _operationLock.WaitAsync();

        try
        {
            await AddOrUpdateForCredentialId(credential);
            await AddForUsername(credential);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task UpdateSignCount(Credential credential, uint signCount)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _operationLock.WaitAsync();

        try
        {
            await UpdateForCredentialId(credential, signCount);
            await UpdateForUsername(credential, signCount);
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private async Task AddOrUpdateForCredentialId(Credential credential)
    {
        var serialized = JsonSerializer.Serialize(credential, _jsonOptions);
        await _cache.SetStringAsync(GetCredentialKey(credential.CredentialId), serialized);
    }

    private async Task AddForUsername(Credential credential)
    {
        var credentials = await Get(credential.Username);
        credentials.Add(credential);

        var serialized = JsonSerializer.Serialize(credentials, _jsonOptions);
        await _cache.SetStringAsync(GetUsernameKey(credential.Username), serialized);
    }

    private async Task UpdateForCredentialId(Credential credential, uint signCount)
    {
        credential.SignCount = signCount;

        await AddOrUpdateForCredentialId(credential);
    }

    private async Task UpdateForUsername(Credential credential, uint signCount)
    {
        var credentials = await Get(credential.Username);

        var targetCredential = credentials.FirstOrDefault(c => c.CredentialId.SequenceEqual(credential.CredentialId));
        if (targetCredential != null)
        {
            targetCredential!.SignCount = signCount;

            var serializedCredentials = JsonSerializer.Serialize(credentials, _jsonOptions);
            await _cache.SetStringAsync(GetUsernameKey(credential.Username), serializedCredentials);
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
