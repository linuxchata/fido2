namespace Shark.Fido2.Core.Abstractions;

public interface IUserIdGenerator
{
    byte[] Get(string? seed = null);
}
