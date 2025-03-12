using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions.Validators;
using Shark.Fido2.Core.Comparers;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators;

internal sealed class UserHandlerValidator : IUserHandlerValidator
{
    private const string UserIsNotTheOwnerOfTheCredential = "User is not the owner of the credential";

    public ValidatorInternalResult Validate(
        Credential credential,
        PublicKeyCredentialAssertion publicKeyCredentialAssertion,
        PublicKeyCredentialRequestOptions requestOptions)
    {
        var userHandle = publicKeyCredentialAssertion.Response.UserHandle?.FromBase64Url();

        // Step 6
        // Identify the user being authenticated and verify that this user is the owner of the public key credential
        // source credentialSource identified by credential.id
        // - If the user was identified before the authentication ceremony was initiated, e.g., via a username or
        // cookie, verify that the identified user is the owner of credentialSource. If response.userHandle is present,
        // let userHandle be its value. Verify that userHandle also maps to the same user.
        if (AreAllowCredentialsPresent(requestOptions))
        {
            if (userHandle != null && userHandle.Length != 0)
            {
                if (!BytesArrayComparer.CompareNullable(credential.UserHandle, userHandle))
                {
                    return ValidatorInternalResult.Invalid(UserIsNotTheOwnerOfTheCredential);
                }
            }
            else
            {
                if (!string.Equals(credential.Username, requestOptions.Username, StringComparison.OrdinalIgnoreCase))
                {
                    return ValidatorInternalResult.Invalid(UserIsNotTheOwnerOfTheCredential);
                }
            }
        }
        // - If the user was not identified before the authentication ceremony was initiated, verify that
        // response.userHandle is present, and that the user identified by this value is the owner of credentialSource.
        else
        {
            if (userHandle == null || userHandle.Length == 0)
            {
                return ValidatorInternalResult.Invalid("User handle is not present");
            }

            if (!BytesArrayComparer.CompareNullable(credential.UserHandle, userHandle))
            {
                return ValidatorInternalResult.Invalid(UserIsNotTheOwnerOfTheCredential);
            }
        }

        return ValidatorInternalResult.Valid();
    }

    private static bool AreAllowCredentialsPresent(PublicKeyCredentialRequestOptions requestOptions)
    {
        return requestOptions.AllowCredentials != null && requestOptions.AllowCredentials.Length != 0;
    }
}
