namespace Shark.Fido2.Models.Responses;

/// <summary>
/// 10.3. User Verification Method Extension (uvm)
/// See: https://www.w3.org/TR/webauthn-2/#sctn-uvm-extension.
/// </summary>
public sealed class ServerUserVerificationMethodOutput
{
    public ulong[]? Entries { get; init; }
}
