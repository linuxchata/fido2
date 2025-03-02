using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Repositories.InMemory;

public class CredentialRepository : ICredentialRepository
{
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

        var credentialIdString = Convert.ToBase64String(id);

        var serializedCredential = await _cache.GetStringAsync(credentialIdString);

        if (!string.IsNullOrWhiteSpace(serializedCredential))
        {
            return JsonSerializer.Deserialize<Credential>(serializedCredential);
        }

        return null;
    }

    public async Task<List<Credential>> Get(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return [];
        }

        var serializedCredentials = await _cache.GetStringAsync(username);

        if (!string.IsNullOrWhiteSpace(serializedCredentials))
        {
            return JsonSerializer.Deserialize<List<Credential>>(serializedCredentials) ?? [];
        }

        return [];
    }

    public async Task Add(Credential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        await AddInternal(credential);
        await AddOrUpdateInternal(credential);
    }

    private async Task AddInternal(Credential credential)
    {
        var credentialIdString = Convert.ToBase64String(credential.CredentialId);

        var serializedCredential = JsonSerializer.Serialize(credential);

        await _cache.SetStringAsync(credentialIdString, serializedCredential);
    }

    private async Task AddOrUpdateInternal(Credential credential)
    {
        var creadentials = new List<Credential>();

        var existingCreadentials = await Get(credential.Username);

        if (existingCreadentials.Count != 0)
        {
            creadentials.AddRange(existingCreadentials);
        }

        creadentials.Add(credential);

        var serializedCredentials = JsonSerializer.Serialize(creadentials);

        await _cache.SetStringAsync(credential.Username, serializedCredentials);
    }
}
