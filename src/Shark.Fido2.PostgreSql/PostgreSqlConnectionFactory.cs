using System.Data;
using System.Diagnostics.CodeAnalysis;
using Npgsql;

namespace Shark.Fido2.PostgreSql;

[ExcludeFromCodeCoverage]
public static class PostgreSqlConnectionFactory
{
    public static IDbConnection GetConnection(string connectionString)
    {
        return new NpgsqlConnection(connectionString);
    }
}