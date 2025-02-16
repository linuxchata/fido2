namespace Shark.Fido2.Domain;

public sealed class AndroidKeyAuthorizationList
{
    public int Purpose { get; set; }

    public bool IsAllApplicationsPresent { get; set; }

    public int Origin { get; set; }
}
