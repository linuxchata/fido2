using System.Text.Json.Serialization;

namespace Shark.Fido2.Models.Responses;

/// <summary>
/// A base server response containing status and error information for FIDO2 operations.
/// </summary>
public class ServerResponse
{
    /// <summary>
    /// Gets or sets the status of the response.
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = null!;

    /// <summary>
    /// Gets or sets an optional error message detailing the reason for failure.
    /// </summary>
    [JsonPropertyName("errorMessage")]
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Creates a successful <see cref="ServerResponse"/> with status "ok".
    /// </summary>
    /// <returns>A new <see cref="ServerResponse"/> representing a successful operation.</returns>
    public static ServerResponse Create()
    {
        return new ServerResponse
        {
            Status = "ok",
        };
    }

    /// <summary>
    /// Creates a failed <see cref="ServerResponse"/> with status "failed" and an optional error message.
    /// </summary>
    /// <param name="errorMessage">The optional error message describing the failure.</param>
    /// <returns>A new <see cref="ServerResponse"/> representing a failed operation.</returns>
    public static ServerResponse CreateFailed(string? errorMessage = null)
    {
        return new ServerResponse
        {
            Status = "failed",
            ErrorMessage = errorMessage,
        };
    }
}
