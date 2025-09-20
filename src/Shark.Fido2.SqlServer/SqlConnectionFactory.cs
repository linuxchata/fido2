using System.Data;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Data.SqlClient;

namespace Shark.Fido2.SqlServer;

[ExcludeFromCodeCoverage]
public static class SqlConnectionFactory
{
    public static IDbConnection GetConnection(string connectionString)
    {
        return new SqlConnection(connectionString);
    }
}
