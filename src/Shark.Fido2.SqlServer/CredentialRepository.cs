using System.Data;
using Dapper;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.SqlServer;

/// <summary>
/// Microsoft SQL Server implementation of the credential repository.
/// </summary>
/// <remarks>
/// This implementation uses Microsoft SQL Server as the persistent data store for FIDO2 credentials.
/// </remarks>
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
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        const string query = @"
            SELECT CredentialId, UserHandle, UserName, UserDisplayName, CredentialPublicKeyJson, SignCount, Transports, CreatedAt, UpdatedAt
            FROM Credential
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId },
            cancellationToken: cancellationToken);

        var entity = await connection.QuerySingleOrDefaultAsync<CredentialEntity>(commandDefinition);

        return entity.ToDomain();
    }

    public async Task<List<CredentialDescriptor>> Get(string userName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userName))
        {
            return [];
        }

        const string query = @"
            SELECT CredentialId, Transports
            FROM Credential
            WHERE UserName = @userName";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { userName },
            cancellationToken: cancellationToken);

        var entities = await connection.QueryAsync<CredentialDescriptorEntity>(commandDefinition);

        return entities.Select(e => e.ToLightweightDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken = default)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return false;
        }

        const string query = @"
            SELECT COUNT(1)
            FROM Credential
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId },
            cancellationToken: cancellationToken);

        var count = await connection.ExecuteScalarAsync<int>(commandDefinition);

        return count > 0;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.CredentialId);
        ArgumentNullException.ThrowIfNullOrEmpty(credential.UserName);
        ArgumentNullException.ThrowIfNull(credential.UserHandle);
        ArgumentNullException.ThrowIfNull(credential.CredentialPublicKey);

        const string query = @"
            INSERT INTO Credential (CredentialId, UserHandle, UserName, UserDisplayName, CredentialPublicKeyJson, SignCount, Transports)
            VALUES (@CredentialId, @UserHandle, @UserName, @UserDisplayName, @CredentialPublicKeyJson, @SignCount, @Transports)";

        var entity = credential.ToEntity();

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new
            {
                entity.CredentialId,
                entity.UserHandle,
                entity.UserName,
                entity.UserDisplayName,
                entity.CredentialPublicKeyJson,
                SignCount = (long)entity.SignCount,
                entity.Transports,
            },
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(commandDefinition);
    }

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        const string query = @"
            UPDATE Credential
            SET SignCount = @SignCount, UpdatedAt = GETUTCDATE(), LastUsedAt = GETUTCDATE()
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { SignCount = (long)signCount, CredentialId = credentialId, },
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(commandDefinition);
    }

    public async Task UpdateLastUsedAt(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        const string query = @"
            UPDATE Credential
            SET LastUsedAt = GETUTCDATE()
            WHERE CredentialId = @CredentialId";

        using var connection = SqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId, },
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(commandDefinition);
    }
}
