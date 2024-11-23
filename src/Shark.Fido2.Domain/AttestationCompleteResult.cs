﻿namespace Shark.Fido2.Domain
{
    public sealed class AttestationCompleteResult
    {
        public string Status { get; set; } = null!;

        public string? Message { get; set; }

        public static AttestationCompleteResult Create()
        {
            return new AttestationCompleteResult { Status = "OK" };
        }

        public static AttestationCompleteResult CreateFailure(string message)
        {
            return new AttestationCompleteResult { Status = "OK", Message = message };
        }
    }
}