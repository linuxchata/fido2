using System.Data;
using Microsoft.Data.SqlClient;

namespace Shark.Fido2.SqlServer;

public static class SqlConnectionFactory
{
    public static IDbConnection GetConnection(string connectionString)
    {
        return new SqlConnection(connectionString);
    }
}
