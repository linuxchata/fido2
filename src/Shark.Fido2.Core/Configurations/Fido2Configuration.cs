namespace Shark.Fido2.Core.Configurations
{
    public sealed class Fido2Configuration
    {
        public const string Name = nameof(Fido2Configuration);

        public string Origin { get; set; } = null!;
    }
}
