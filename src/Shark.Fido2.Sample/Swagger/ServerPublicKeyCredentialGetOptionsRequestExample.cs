using Shark.Fido2.Models.Requests;
using Swashbuckle.AspNetCore.Filters;

namespace Shark.Fido2.Sample.Swagger;

public class ServerPublicKeyCredentialGetOptionsRequestExample :
    IExamplesProvider<ServerPublicKeyCredentialGetOptionsRequest>
{
    public ServerPublicKeyCredentialGetOptionsRequest GetExamples()
    {
        return new ServerPublicKeyCredentialGetOptionsRequest
        {
            Username = "shark",
            UserVerification = "required",
        };
    }
}
