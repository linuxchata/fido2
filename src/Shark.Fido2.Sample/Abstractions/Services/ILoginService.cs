namespace Shark.Fido2.Sample.Abstractions.Services;

/// <summary>
/// The interface representing the logic to manage user login and logout.
/// </summary>
public interface ILoginService
{
    /// <summary>
    /// Logs in a user with cookie authentication.
    /// </summary>
    /// <param name="httpContext">The HTTP context.</param>
    /// <param name="username">The username to authenticate.</param>
    /// <returns>A task.</returns>
    Task Login(HttpContext httpContext, string? username);

    /// <summary>
    /// Logs out the authenticated user.
    /// </summary>
    /// <param name="httpContext">The HTTP context.</param>
    /// <returns>A task.</returns>
    Task Logout(HttpContext httpContext);
}
