namespace Shark.Fido2.Metadata.Core.Abstractions;

public interface IMetadataService
{
    Task Refresh(CancellationToken cancellationToken);
}
