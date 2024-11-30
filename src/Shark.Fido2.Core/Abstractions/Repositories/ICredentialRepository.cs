using System.Threading.Tasks;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Abstractions.Repositories
{
    public interface ICredentialRepository
    {
        Task<Credential?> Get(byte[]? id);
    }
}
