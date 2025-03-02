﻿using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Repositories.InMemory;

public sealed class CredentialRepository : ICredentialRepository
{
    private const string CredentialKeyPrefix = "credential:";
    private const string UsernameKeyPrefix = "user:";

    private static readonly SemaphoreSlim _semaphore = new(1, 1);
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
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

        var serializedCredential = await _cache.GetStringAsync(GetCredentialKey(id));

        if (!string.IsNullOrWhiteSpace(serializedCredential))
        {
            return JsonSerializer.Deserialize<Credential>(serializedCredential, _jsonOptions);
        }

        return null;
    }

    public async Task<List<Credential>> Get(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var serializedCredentials = await _cache.GetStringAsync(GetUsernameKey(username));

        if (!string.IsNullOrWhiteSpace(serializedCredentials))
        {
            return JsonSerializer.Deserialize<List<Credential>>(serializedCredentials, _jsonOptions) ?? [];
        }

        return [];
    }

    public async Task Add(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await _semaphore.WaitAsync();

        try
        {
            await AddInternal(credential);
            await AddOrUpdateInternal(credential);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task AddInternal(Credential credential)
    {
        var serializedCredential = JsonSerializer.Serialize(credential, _jsonOptions);

        await _cache.SetStringAsync(GetCredentialKey(credential.CredentialId), serializedCredential);
    }

    private async Task AddOrUpdateInternal(Credential credential)
    {
        var credentials = new List<Credential>();

        var existingCredentials = await Get(credential.Username);

        if (existingCredentials.Count != 0)
        {
            credentials.AddRange(existingCredentials);
        }

        credentials.Add(credential);

        var serializedCredentials = JsonSerializer.Serialize(credentials, _jsonOptions);

        await _cache.SetStringAsync(GetUsernameKey(credential.Username), serializedCredentials);
    }

    private static string GetCredentialKey(byte[] id)
    {
        return $"{CredentialKeyPrefix}{Convert.ToBase64String(id)}";
    }

    private static string GetUsernameKey(string username)
    {
        return $"{UsernameKeyPrefix}{username}";
    }
}
