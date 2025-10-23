using System.Data;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Shark.Fido2.Core.Abstractions.Repositories;
using Shark.Fido2.Core.Entities;
using Shark.Fido2.Core.Mappers;
using Shark.Fido2.Domain;

namespace Shark.Fido2.PostgreSql;

/// <summary>
/// PostgreSQL implementation of the credential repository.
/// </summary>
/// <remarks>
/// This implementation uses PostgreSQL as the persistent data store for FIDO2 credentials.
/// </remarks>
[ExcludeFromCodeCoverage]
internal sealed class CredentialRepository : ICredentialRepository
{
    private readonly string _connectionString;

    public CredentialRepository(DatabaseSettings databaseSettings)
    {
        _connectionString = databaseSettings.DefaultConnection ??
            throw new ArgumentNullException(nameof(databaseSettings));
    }

    public async Task<Credential?> Get(byte[]? credentialId, CancellationToken cancellationToken)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return null;
        }

        const string query = @"
            SELECT
                credential_id AS ""CredentialId"",
                user_handle AS ""UserHandle"",
                user_name AS ""UserName"",
                user_display_name AS ""UserDisplayName"",
                credential_public_key_json AS ""CredentialPublicKeyJson"",
                sign_count AS ""SignCount"",
                transports AS ""Transports"",
                created_at AS ""CreatedAt"",
                updated_at AS ""UpdatedAt"",
                last_used_at AS ""LastUsedAt""
            FROM credential
            WHERE credential_id = @CredentialId";

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId },
            cancellationToken: cancellationToken);

        var entity = await connection.QuerySingleOrDefaultAsync<CredentialEntity>(commandDefinition);

        return entity.ToDomain();
    }

    public async Task<List<CredentialDescriptor>> Get(string userName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(userName))
        {
            return [];
        }

        const string query = @"
            SELECT credential_id AS ""CredentialId"", transports AS ""Transports""
            FROM credential
            WHERE user_name = @userName";

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { userName },
            cancellationToken: cancellationToken);

        var entities = await connection.QueryAsync<CredentialDescriptorEntity>(commandDefinition);

        return entities.Select(e => e.ToLightweightDomain()!).ToList();
    }

    public async Task<bool> Exists(byte[]? credentialId, CancellationToken cancellationToken)
    {
        if (credentialId == null || credentialId.Length == 0)
        {
            return false;
        }

        const string query = @"
            SELECT COUNT(1)
            FROM credential
            WHERE credential_id = @CredentialId";

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId },
            cancellationToken: cancellationToken);

        var count = await connection.ExecuteScalarAsync<int>(commandDefinition);

        return count > 0;
    }

    public async Task Add(Credential credential, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(credential.CredentialId);
        ArgumentNullException.ThrowIfNullOrEmpty(credential.UserName);
        ArgumentNullException.ThrowIfNull(credential.UserHandle);
        ArgumentNullException.ThrowIfNull(credential.CredentialPublicKey);

        const string query = @"
            INSERT INTO credential (credential_id, user_handle, user_name, user_display_name, credential_public_key_json, sign_count, transports)
            VALUES (@CredentialId, @UserHandle, @UserName, @UserDisplayName, @CredentialPublicKeyJson, @SignCount, @Transports)";

        var entity = credential.ToEntity();

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

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

    public async Task UpdateSignCount(byte[] credentialId, uint signCount, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        const string query = @"
            UPDATE credential
            SET sign_count = @SignCount, updated_at = CURRENT_TIMESTAMP, last_used_at = CURRENT_TIMESTAMP
            WHERE credential_id = @CredentialId";

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { SignCount = (long)signCount, CredentialId = credentialId, },
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(commandDefinition);
    }

    public async Task UpdateLastUsedAt(byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        const string query = @"
            UPDATE credential
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE credential_id = @CredentialId";

        using var connection = PostgreSqlConnectionFactory.GetConnection(_connectionString);

        var commandDefinition = new CommandDefinition(
            query,
            new { CredentialId = credentialId, },
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(commandDefinition);
    }
}
