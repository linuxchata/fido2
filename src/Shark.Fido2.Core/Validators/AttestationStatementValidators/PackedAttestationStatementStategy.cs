﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators
{
    /// <summary>
    /// 8.2. Packed Attestation Statement Format
    /// </summary>
    internal class PackedAttestationStatementStategy : IAttestationStatementStategy
    {
        public ValidatorInternalResult Validate(
            AttestationObjectData attestationObjectData,
            ClientData clientData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            var attestationStatement = attestationObjectData.AttestationStatement;
            if (attestationStatement == null)
            {
                throw new ArgumentNullException(nameof(attestationStatement));
            }

            if (!(attestationStatement is Dictionary<string, object> attestationStatementDict))
            {
                throw new ArgumentNullException(nameof(attestationStatement), "Attestation statement cannot be read");
            }

            if (!attestationStatementDict.TryGetValue("alg", out var algorithm) || !(algorithm is int))
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
            }

            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            var attestedCredentialData = attestationObjectData.AuthenticatorData!.AttestedCredentialData;
            if (attestedCredentialData.CredentialPublicKey.Algorithm != (int)algorithm)
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
            }

            if (!attestationStatementDict.TryGetValue("sig", out var signature) || !(signature is byte[]))
            {
                return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
            }

            // Verify that sig is a valid signature over the concatenation of authenticatorData and
            // clientDataHash using the credential public key with alg.
            var concatenatedData = GetConcatenatedData(
                attestationObjectData.AuthenticatorRawData,
                clientData.ClientDataHash);

            using var rsa = RSA.Create(new RSAParameters
            {
                Modulus = attestedCredentialData.CredentialPublicKey.Modulus,
                Exponent = attestedCredentialData.CredentialPublicKey.Exponent,
            });

            var isValid = rsa.VerifyData(
                concatenatedData,
                (byte[])signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return ValidatorInternalResult.Valid();
        }

        private static byte[] GetConcatenatedData(byte[] authenticatorData, byte[] clientDataHash)
        {
            var concatenatedData = new byte[authenticatorData.Length + clientDataHash.Length];
            Buffer.BlockCopy(authenticatorData, 0, concatenatedData, 0, authenticatorData.Length);
            Buffer.BlockCopy(clientDataHash, 0, concatenatedData, authenticatorData.Length, clientDataHash.Length);

            return concatenatedData;
        }
    }
}
