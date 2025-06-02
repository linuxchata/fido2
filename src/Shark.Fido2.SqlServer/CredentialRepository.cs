using System.Data;
using Dapper;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.SqlServer;

internal sealed class CredentialRepository : ICredentialRepository
{
    private readonly string _connectionString;

    public CredentialRepository(DatabaseSettings databaseSettings)
    {
        _connectionString = databaseSettings.DefaultConnection ??
            throw new ArgumentNullException(nameof(databaseSettings));
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null)
        {
            return null;
        }

        const string sql = @"
            SELECT CredentialId, UserHandle, UserName, UserDisplayName, CredentialPublicKeyJson, SignCount, Transports, CreatedAt, UpdatedAt
            FROM Credential
            WHERE CredentialId = @CredentialId"
        ;

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var entity = await connection.QuerySingleOrDefaultAsync<CredentialEntity>(
            sql,
            new { CredentialId = credentialId });

        return entity.ToDomain();
    }

    public async Task<List<CredentialDescriptor>> Get(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username))
        {
            return [];
        }

        const string sql = @"
            SELECT CredentialId, Transports
            FROM Credential
            WHERE UserName = @username";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var entities = await connection.QueryAsync<CredentialEntity>(sql, new { username });

        return entities.Select(e => e.ToLightweightDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? id, CancellationToken cancellationToken = default)
    {
        if (id == null)
        {
            return false;
        }

        const string sql = @"
            SELECT COUNT(1)
            FROM Credential
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var count = await connection.ExecuteScalarAsync<int>(sql, new { CredentialId = id });

        return count > 0;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        const string sql = @"
            INSERT INTO Credential (CredentialId, UserHandle, UserName, UserDisplayName, CredentialPublicKeyJson, SignCount, Transports)
            VALUES (@CredentialId, @UserHandle, @UserName, @UserDisplayName, @CredentialPublicKeyJson, @SignCount, @Transports)";

        var entity = credential.ToEntity();

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        await connection.ExecuteAsync(
            sql,
            new
            {
                entity.CredentialId,
                entity.UserHandle,
                entity.UserName,
                entity.UserDisplayName,
                entity.CredentialPublicKeyJson,
                SignCount = (long)entity.SignCount,
                entity.Transports,
            });
    }

    public async Task UpdateSignCount(Credential credential, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        const string sql = @"
            UPDATE Credential
            SET SignCount = @SignCount, UpdatedAt = GETUTCDATE()
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        await connection.ExecuteAsync(
            sql,
            new
            {
                SignCount = (long)signCount,
                credential.CredentialId,
            });
    }
}
