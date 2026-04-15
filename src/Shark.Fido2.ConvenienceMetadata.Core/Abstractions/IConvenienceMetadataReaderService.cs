using Shark.Fido2.ConvenienceMetadata.Core.Models;

namespace Shark.Fido2.ConvenienceMetadata.Core.Abstractions;

/// <summary>
/// The interface representing the logic to read convenience metadata BLOB objects.
/// </summary>
public interface IConvenienceMetadataReaderService
{
    /// <summary>
    /// Reads a convenience metadata BLOB object.
    /// </summary>
    /// <param name="metadataBlob">The metadata BLOB content.</param>
    /// <returns>The convenience metadata payload.</returns>
    ConvenienceMetadataPayload Read(string metadataBlob);
}
