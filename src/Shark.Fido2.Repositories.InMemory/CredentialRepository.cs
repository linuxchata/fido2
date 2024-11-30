using System;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Repositories.InMemory
{
    public class CredentialRepository : ICredentialRepository
    {
        private readonly IDistributedCache _cache;

        public CredentialRepository(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task<Credential?> Get(byte[]? id)
        {
            if (id == null)
            {
                return null;
            }

            var credentialIdString = Convert.ToBase64String(id);

            var serializedItem = await _cache.GetStringAsync(credentialIdString);

            if (!string.IsNullOrWhiteSpace(serializedItem))
            {
                return JsonSerializer.Deserialize<Credential>(serializedItem);
            }

            return null;
        }

        public async Task Add(Credential credential)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            var credentialIdString = Convert.ToBase64String(credential.CredentialId);

            var serializedItem = JsonSerializer.Serialize(credential);

            await _cache.SetStringAsync(credentialIdString, serializedItem);
        }
    }
}
