﻿using System.Security.Cryptography;

namespace Shark.Fido2.Domain;

public sealed class Ec2Algorithm
{
    public ECCurve Curve { get; set; }

    public HashAlgorithmName HashAlgorithmName { get; set; }
}
