namespace Shark.Fido2.Sample.Abstractions.Services;

public interface ILoginService
{
    Task Login(HttpContext httpContext, string? username);
}
