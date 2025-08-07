using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Shark.Fido2.Core.Services;

namespace Shark.Fido2.Core.Tests.Services;

[TestFixture]
internal class AndroidSafetyNetJwsResponseParserServiceTests
{
    private AndroidSafetyNetJwsResponseParserService _sut = null!;
    private JwtSecurityTokenHandler _tokenHandler = null!;
    private SigningCredentials _signingCredentials = null!;

    [SetUp]
    public void Setup()
    {
        _sut = new AndroidSafetyNetJwsResponseParserService();
        _tokenHandler = new JwtSecurityTokenHandler();

        // Create signing credentials for test JWT tokens
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('a', 32)));
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    [Test]
    public void Parse_WhenResponseIsNull_ThenThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.That(() => _sut.Parse(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Parse_WhenResponseIsEmpty_ThenReturnsNull()
    {
        // Arrange
        var response = Array.Empty<byte>();

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Parse_WhenJwtTokenIsInvalid_ThenReturnsNull()
    {
        // Arrange
        var invalidToken = "invalid token";
        var response = Encoding.UTF8.GetBytes(invalidToken);

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void Parse_WhenJwtTokenIsValid_ThenReturnsCorrectJwsResponse()
    {
        // Arrange
        var claims = new[]
        {
            new Claim("nonce", "test-nonce"),
            new Claim("ctsProfileMatch", "true"),
            new Claim("basicIntegrity", "true"),
            new Claim("apkPackageName", "com.google.android.gms"),
            new Claim("apkCertificateDigestSha256", "test-cert-digest"),
            new Claim("apkDigestSha256", "test-digest"),
            new Claim("timestampMs", "1234567890"),
        };

        var jwtHeader = new JwtHeader(_signingCredentials)
        {
            { "x5c", new List<object> { "cert1", "cert2" } },
        };

        var jwtSecurityToken = new JwtSecurityToken(
            header: jwtHeader,
            payload: new JwtPayload(claims));

        var jwtToken = _tokenHandler.WriteToken(jwtSecurityToken);
        var response = Encoding.UTF8.GetBytes(jwtToken);

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.RawToken, Is.EqualTo(jwtToken));
        Assert.That(result.Algorithm, Is.EqualTo(SecurityAlgorithms.HmacSha256));
        Assert.That(result.Certificates, Has.Count.EqualTo(2));
        Assert.That(result.Nonce, Is.EqualTo("test-nonce"));
        Assert.That(result.CtsProfileMatch, Is.True);
        Assert.That(result.BasicIntegrity, Is.True);
        Assert.That(result.ApkPackageName, Is.EqualTo("com.google.android.gms"));
        Assert.That(result.ApkCertificateDigestSha256, Is.EqualTo("test-cert-digest"));
        Assert.That(result.ApkDigestSha256, Is.EqualTo("test-digest"));
        Assert.That(result.TimestampMs, Is.EqualTo("1234567890"));
    }

    [Test]
    public void Parse_WhenJwtTokenIsAndroidSafetyNetJwsResponse_ThenReturnsCorrectJwsResponse()
    {
        // Arrange
        var jwtToken = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFaWpDQ0EzS2dBd0lCQWdJSVlrWW81RjBnODZrd0RRWUpLb1pJaHZjTkFRRUxCUUF3VkRFTE1Ba0dBMVVFQmhNQ1ZWTXhIakFjQmdOVkJBb1RGVWR2YjJkc1pTQlVjblZ6ZENCVFpYSjJhV05sY3pFbE1DTUdBMVVFQXhNY1IyOXZaMnhsSUVsdWRHVnlibVYwSUVGMWRHaHZjbWwwZVNCSE16QWVGdzB4TnpFeU1EUXhNekU0TkROYUZ3MHhPREV5TURNd01EQXdNREJhTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlEQXBEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIREExTmIzVnVkR0ZwYmlCV2FXVjNNUk13RVFZRFZRUUtEQXBIYjI5bmJHVWdTVzVqTVJzd0dRWURWUVFEREJKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNVajh3WW9QaXhLYmJWOHNnWWd2TVRmWCtkSXNGVE9rZ0tPbGhUMGkwYmNERlpLMnJPeEpaMnVTTFNWaFl2aXBaTkUzSEpRWXV1WXdGaml5K3lrZmF0QUdTalJ6RjFiMzF1NDMvN29HNWpNaDNTMzdhbHdqVWI4Q1dpVHhvaXBWT1l3S0t6dVV5a3FFQ3RqbGhKNEFrV2FEUytaeEtFcU9hZTl0bkNnZUhsbFpFL09SZ2VNYXgyWE5Db0g2c3JURVJja3NqelpackFXeEtzZGZ2VnJYTnpDUjlEeFZBU3VJNkx6d2g4RFNsMkVPb2tic2FuWisrL0pxTWVBQkZmUHdqeXdyYjBwckVVeTBwYWVWc3VkKzBwZWV4Sy81K0U2a3BZR0s0WksybmtvVkx1Z0U1dGFIckFqODNRK1BPYmJ2T3pXY0ZrcG5WS3lqbzZLUUFtWDZXSkFnTUJBQUdqZ2dGR01JSUJRakFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQVRBZEJnTlZIUkVFRmpBVWdoSmhkSFJsYzNRdVlXNWtjbTlwWkM1amIyMHdhQVlJS3dZQkJRVUhBUUVFWERCYU1DMEdDQ3NHQVFVRkJ6QUNoaUZvZEhSd09pOHZjR3RwTG1kdmIyY3ZaM055TWk5SFZGTkhTVUZITXk1amNuUXdLUVlJS3dZQkJRVUhNQUdHSFdoMGRIQTZMeTl2WTNOd0xuQnJhUzVuYjI5bkwwZFVVMGRKUVVjek1CMEdBMVVkRGdRV0JCUUc4SXJRdEZSNkNVU2tpa2IzYWltc20yNmNCVEFNQmdOVkhSTUJBZjhFQWpBQU1COEdBMVVkSXdRWU1CYUFGSGZDdUZDYVozWjJzUzNDaHRDRG9INm1mcnBMTUNFR0ExVWRJQVFhTUJnd0RBWUtLd1lCQkFIV2VRSUZBekFJQmdabmdRd0JBZ0l3TVFZRFZSMGZCQ293S0RBbW9DU2dJb1lnYUhSMGNEb3ZMMk55YkM1d2Eya3VaMjl2Wnk5SFZGTkhTVUZITXk1amNtd3dEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRi9Sek5uQzVEekJVQnRuaDJudEpMV0VRaDl6RWVGWmZQTDlRb2tybEFvWGdqV2dOOHBTUlUxbFZHSXB0ek14R2h5My9PUlJaVGE2RDJEeThodkNEckZJMytsQ1kwMU1MNVE2WE5FNVJzMmQxUmlacE1zekQ0S1FaTkczaFowQkZOUS9janJDbUxCT0dLa0VVMWRtQVhzRkpYSmlPcjJDTlRCT1R1OUViTFdoUWZkQ0YxYnd6eXUrVzZiUVN2OFFEbjVPZE1TL1BxRTFkRWdldC82RUlSQjc2MUtmWlErL0RFNkxwM1RyWlRwT0ZERGdYaCtMZ0dPc3doRWxqOWMzdlpIR0puaGpwdDhya2Jpci8ydUxHZnhsVlo0SzF4NURSTjBQVUxkOXlQU21qZythajErdEh3STFtUW1aVlk3cXZPNURnaE94aEpNR2x6NmxMaVptem9nPSIsIk1JSUVYRENDQTBTZ0F3SUJBZ0lOQWVPcE1CejhjZ1k0UDVwVEhUQU5CZ2txaGtpRzl3MEJBUXNGQURCTU1TQXdIZ1lEVlFRTEV4ZEhiRzlpWVd4VGFXZHVJRkp2YjNRZ1EwRWdMU0JTTWpFVE1CRUdBMVVFQ2hNS1IyeHZZbUZzVTJsbmJqRVRNQkVHQTFVRUF4TUtSMnh2WW1Gc1UybG5iakFlRncweE56QTJNVFV3TURBd05ESmFGdzB5TVRFeU1UVXdNREF3TkRKYU1GUXhDekFKQmdOVkJBWVRBbFZUTVI0d0hBWURWUVFLRXhWSGIyOW5iR1VnVkhKMWMzUWdVMlZ5ZG1salpYTXhKVEFqQmdOVkJBTVRIRWR2YjJkc1pTQkpiblJsY201bGRDQkJkWFJvYjNKcGRIa2dSek13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREtVa3ZxSHYvT0pHdW8ybklZYU5WV1hRNUlXaTAxQ1haYXo2VElITEdwL2xPSis2MDAvNGhibjd2bjZBQUIzRFZ6ZFFPdHM3RzVwSDBySm5uT0ZVQUs3MUc0bnpLTWZIQ0dVa3NXL21vbmErWTJlbUpRMk4rYWljd0pLZXRQS1JTSWdBdVBPQjZBYWhoOEhiMlhPM2g5UlVrMlQwSE5vdUIyVnp4b01YbGt5VzdYVVI1bXc2SmtMSG5BNTJYRFZvUlRXa050eTVvQ0lOTHZHbW5Sc0oxem91QXFZR1ZRTWMvN3N5Ky9FWWhBTHJWSkVBOEtidHlYK3I4c253VTVDMWhVcndhVzZNV09BUmE4cUJwTlFjV1RrYUllb1l2eS9zR0lKRW1qUjB2RkV3SGRwMWNTYVdJcjYvNGc3Mm43T3FYd2ZpbnU3WllXOTdFZm9PU1FKZUF6QWdNQkFBR2pnZ0V6TUlJQkx6QU9CZ05WSFE4QkFmOEVCQU1DQVlZd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3SFFZRFZSME9CQllFRkhmQ3VGQ2FaM1oyc1MzQ2h0Q0RvSDZtZnJwTE1COEdBMVVkSXdRWU1CYUFGSnZpQjFkbkhCN0FhZ2JlV2JTYUxkL2NHWVl1TURVR0NDc0dBUVVGQndFQkJDa3dKekFsQmdnckJnRUZCUWN3QVlZWmFIUjBjRG92TDI5amMzQXVjR3RwTG1kdmIyY3ZaM055TWpBeUJnTlZIUjhFS3pBcE1DZWdKYUFqaGlGb2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwyZHpjakl2WjNOeU1pNWpjbXd3UHdZRFZSMGdCRGd3TmpBMEJnWm5nUXdCQWdJd0tqQW9CZ2dyQmdFRkJRY0NBUlljYUhSMGNITTZMeTl3YTJrdVoyOXZaeTl5WlhCdmMybDBiM0o1THpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUhMZUpsdVJUN2J2czI2Z3lBWjhzbzgxdHJVSVNkN080NXNrRFVtQWdlMWNueGhHMVAyY05tU3hiV3NvaUN0MmV1eDlMU0QrUEFqMkxJWVJGSFczMS82eG9pYzFrNHRiV1hrRENqaXIzN3hUVE5xUkFNUFV5RlJXU2R2dCtubFBxd25iOE9hMkkvbWFTSnVrY3hEak5TZnBEaC9CZDFsWk5nZGQvOGNMZHNFMyt3eXB1Zko5dVhPMWlRcG5oOXpidUZJd3NJT05HbDFwM0E4Q2d4a3FJL1VBaWgzSmFHT3FjcGNkYUNJemtCYVI5dVlRMVg0azJWZzVBUFJMb3V6Vnk3YThJVms2d3V5NnBtK1Q3SFQ0TFk4aWJTNUZFWmxmQUZMU1c4TndzVno5U0JLMlZxbjFOMFBJTW41eEE2TlpWYzdvODM1RExBRnNoRVdmQzdUSWUzZz09Il19.eyJub25jZSI6ImxXa0lqeDdPNHlNcFZBTmR2UkRYeXVPUk1Gb25VYlZadTQvWHk3SXB2ZFJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFLZ2x4SHlmblJLQVpWcWlKZElxdHFmNEk5ZHgwb082L3pBTzhUbkRvanZFWkFxMkRaa0J5STFmY29XVlFFcS9PM0ZMSDVhT3d6YnJyeHJKNjVVNWRZcWxBUUlESmlBQklWZ2doNU9KZllSRHpWR0lvd0txVTU3QW5vVmpqZG1takdpOXpsTWtqQVZWOURBaVdDRHIwaVNpMHZpSUtOUE1USWROMjhnV05ta2N3T3I2RFF4NjZNUGZmM09kbSt1NmVKcUxCbDFIMlMydHJBQkhMaW5rbnN5Vk1QbS9CTlVWWjJKRmxyODAiLCJ0aW1lc3RhbXBNcyI6MTUyODkxMTYzNDM4NSwiYXBrUGFja2FnZU5hbWUiOiJjb20uZ29vZ2xlLmFuZHJvaWQuZ21zIiwiYXBrRGlnZXN0U2hhMjU2IjoiSk9DM1Vrc2xzdVZ6MTNlT3BuRkk5QnBMb3FCZzlrMUY2T2ZhUHRCL0dqTT0iLCJjdHNQcm9maWxlTWF0Y2giOmZhbHNlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyJHWFd5OFhGM3ZJbWwzL01mbm1TbXl1S0JwVDNCMGRXYkhSUi80Y2dxK2dBPSJdLCJiYXNpY0ludGVncml0eSI6ZmFsc2UsImFkdmljZSI6IlJFU1RPUkVfVE9fRkFDVE9SWV9ST00sTE9DS19CT09UTE9BREVSIn0.iCF6D2os8DYuDVOnt3zDJB2mSXnZjtWJtl_jzSDx5MrRC9A2fmFBZ6z5kpQZ2MiQ7ootj9WkHMgxqIhrX3dlh2POHAwkIS34ySjLVNsSPprE84eZgqSFLMEYT0GR2eVLHAMPN8n5R8K6buDOGF3nSi6GKzG57Zll8CSob2yiAS9r7spdA6H0TDH-NGzSdbMIId8fZD1dzFKNQr77b6lbIAFgQbRZBrnp-e-H4iH6d21oN2NAYRnR5YURacP6kGGj2cFxswE2908wxv9hiYNKNojeeu8Xc4It7PbhlAuO7ywhQFA81iPCCFm11B8cfUXbWA8l_2ttNPBEMGM6-Z6VyQ";
        var response = Encoding.UTF8.GetBytes(jwtToken);

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.RawToken, Is.EqualTo(jwtToken));
        Assert.That(result.Algorithm, Is.EqualTo(SecurityAlgorithms.RsaSha256));
        Assert.That(result.Certificates, Has.Count.EqualTo(2));
        Assert.That(result.Nonce, Is.EqualTo("lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4/Xy7IpvdRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKglxHyfnRKAZVqiJdIqtqf4I9dx0oO6/zAO8TnDojvEZAq2DZkByI1fcoWVQEq/O3FLH5aOwzbrrxrJ65U5dYqlAQIDJiABIVggh5OJfYRDzVGIowKqU57AnoVjjdmmjGi9zlMkjAVV9DAiWCDr0iSi0viIKNPMTIdN28gWNmkcwOr6DQx66MPff3Odm+u6eJqLBl1H2S2trABHLinknsyVMPm/BNUVZ2JFlr80"));
        Assert.That(result.CtsProfileMatch, Is.False);
        Assert.That(result.BasicIntegrity, Is.False);
        Assert.That(result.ApkPackageName, Is.EqualTo("com.google.android.gms"));
        Assert.That(result.ApkCertificateDigestSha256, Is.EqualTo("GXWy8XF3vIml3/MfnmSmyuKBpT3B0dWbHRR/4cgq+gA="));
        Assert.That(result.ApkDigestSha256, Is.EqualTo("JOC3UkslsuVz13eOpnFI9BpLoqBg9k1F6OfaPtB/GjM="));
        Assert.That(result.TimestampMs, Is.EqualTo("1528911634385"));
    }

    [Test]
    public void Parse_WhenJwtTokenIsWithInvalidBooleanClaims_ThenHandlesInvalidValuesGracefully()
    {
        // Arrange
        var claims = new[]
        {
            new Claim("ctsProfileMatch", "invalid"),
            new Claim("basicIntegrity", "invalid"),
        };

        var jwtSecurityToken = new JwtSecurityToken(
            header: new JwtHeader(_signingCredentials),
            payload: new JwtPayload(claims));

        var jwtToken = _tokenHandler.WriteToken(jwtSecurityToken);
        var response = Encoding.UTF8.GetBytes(jwtToken);

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.CtsProfileMatch, Is.Null);
        Assert.That(result.BasicIntegrity, Is.Null);
    }

    [Test]
    public void Parse_WhenJwtTokenIsWithMissingClaims_ThenHandlesMissingValuesGracefully()
    {
        // Arrange
        var claims = new[]
        {
            new Claim("nonce", "test-nonce"),
        };

        var jwtSecurityToken = new JwtSecurityToken(
            header: new JwtHeader(_signingCredentials),
            payload: new JwtPayload(claims));

        var jwtToken = _tokenHandler.WriteToken(jwtSecurityToken);
        var response = Encoding.UTF8.GetBytes(jwtToken);

        // Act
        var result = _sut.Parse(response);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Nonce, Is.EqualTo("test-nonce"));
        Assert.That(result.CtsProfileMatch, Is.Null);
        Assert.That(result.BasicIntegrity, Is.Null);
        Assert.That(result.ApkPackageName, Is.Null);
        Assert.That(result.ApkCertificateDigestSha256, Is.Null);
        Assert.That(result.ApkDigestSha256, Is.Null);
        Assert.That(result.TimestampMs, Is.Null);
    }
}