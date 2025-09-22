using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NBomber.Contracts.Stats;
using NBomber.CSharp;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.Core.Helpers;
using Shark.Fido2.Domain.Enums;
using Shark.Fido2.Domain.Options;
using Shark.Fido2.InMemory;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Performance.Tests;

public class PerformanceTestScenarios
{
    private const string NoneAttestation = "NoneAttestation.json";
    private const string NoneCreationOptions = "NoneCreationOptions.json";
    private const string NoneAssertion = "NoneAssertion.json";
    private const string NoneRequestOptions = "NoneRequestOptions.json";

    private readonly ConcurrentBag<(string CredentialId, string Name)> _enduranceTestUsers = [];
    private readonly UserIdGenerator _userIdGenerator = new();

    private ServiceProvider? _serviceProvider;

    [SetUp]
    public void Setup()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .Build();

        var services = new ServiceCollection();
        services.AddFido2(configuration);
        services.AddFido2InMemoryStore();
        services.AddLogging();
        _serviceProvider = services.BuildServiceProvider();
    }

    [TearDown]
    public void TearDown()
    {
        _enduranceTestUsers.Clear();
        _serviceProvider?.Dispose();
    }

    [Test]
    public void SpikeLoadTest()
    {
        var scenario = Scenario
            .Create("spike_load_test", async context =>
            {
                var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
                var attestationData = DataReader.ReadAttestationData(NoneAttestation);
                var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);

                var result = await attestation.CompleteRegistration(
                    attestationData,
                    creationOptions,
                    CancellationToken.None);

                return result != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(
                Simulation.Inject(rate: 5, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 5, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)));

        NBomberRunner
            .RegisterScenarios(scenario)
            .WithReportFolder("nbomber_reports/spike_test")
            .Run();
    }

    [Test]
    public void StressTest()
    {
        var scenario = Scenario
            .Create("stress_test", async context =>
            {
                var assertion = _serviceProvider!.GetRequiredService<IAssertion>();
                var attestation = _serviceProvider!.GetRequiredService<IAttestation>();

                // Register credential
                var attestationData = DataReader.ReadAttestationData(NoneAttestation);
                var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);
                await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

                // Authenticate
                var assertionData = DataReader.ReadAssertionData(NoneAssertion);
                var requestOptions = DataReader.ReadRequestOptions(NoneRequestOptions);

                var result = await assertion.CompleteAuthentication(
                    assertionData,
                    requestOptions,
                    CancellationToken.None);

                return result != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(2)));

        NBomberRunner
            .RegisterScenarios(scenario)
            .WithReportFolder("nbomber_reports/stress_test")
            .Run();
    }

    [Test]
    public void EnduranceTest()
    {
        var assertion = _serviceProvider!.GetRequiredService<IAssertion>();
        var attestation = _serviceProvider!.GetRequiredService<IAttestation>();

        var registrationScenario = Scenario
            .Create("endurance_registration", async context =>
            {
                var attestationData = DataReader.ReadAttestationData(NoneAttestation);
                var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);

                var username = $"Name_{Guid.NewGuid().ToString().ToLower()}";
                creationOptions.User = new PublicKeyCredentialUserEntity
                {
                    Id = _userIdGenerator.Get(username),
                    Name = username,
                    DisplayName = $"DisplayName_{Guid.NewGuid().ToString().ToLower()}",
                };

                var credentialId = GetCredentialId();
                attestationData.Id = credentialId;
                attestationData.RawId = credentialId;

                var result = await attestation.CompleteRegistration(
                    attestationData,
                    creationOptions,
                    CancellationToken.None);

                _enduranceTestUsers.Add((credentialId, username));

                return result != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(
                Simulation.Inject(rate: 2, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(5)));

        var authenticationScenario = Scenario
            .Create("endurance_authentication", async context =>
            {
                if (_enduranceTestUsers.IsEmpty)
                {
                    return Response.Ok();
                }

                var assertionData = DataReader.ReadAssertionData(NoneAssertion);
                var requestOptionsTemplate = DataReader.ReadRequestOptions(NoneRequestOptions);

                var session = _enduranceTestUsers.ElementAt(new Random().Next(0, _enduranceTestUsers.Count));
                var requestOptions = new PublicKeyCredentialRequestOptions
                {
                    Challenge = requestOptionsTemplate.Challenge,
                    Timeout = requestOptionsTemplate.Timeout,
                    RpId = requestOptionsTemplate.RpId,
                    AllowCredentials =
                    [
                        new PublicKeyCredentialDescriptor
                        {
                            Id = session.CredentialId.FromBase64Url(),
                            Transports = [AuthenticatorTransport.Hybrid, AuthenticatorTransport.Internal],
                        },
                    ],
                    UserVerification = requestOptionsTemplate.UserVerification,
                    Username = session.Name,
                };

                assertionData.Id = session.CredentialId;
                assertionData.RawId = session.CredentialId;

                var result = await assertion.CompleteAuthentication(
                    assertionData,
                    requestOptions,
                    CancellationToken.None);

                return result != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(
                Simulation.Inject(rate: 8, interval: TimeSpan.FromSeconds(5), during: TimeSpan.FromMinutes(5)));

        NBomberRunner
            .RegisterScenarios(registrationScenario, authenticationScenario)
            .WithReportFolder("nbomber_reports/endurance_test")
            .WithReportFormats(ReportFormat.Html)
            .Run();
    }

    [Test]
    public void VolumeTest()
    {
        var scenario = Scenario
            .Create("volume_test", async context =>
            {
                var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
                var attestationData = DataReader.ReadAttestationData(NoneAttestation);
                var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);

                var result = await attestation.CompleteRegistration(
                    attestationData,
                    creationOptions,
                    CancellationToken.None);

                return result != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 200, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(3)));

        NBomberRunner
            .RegisterScenarios(scenario)
            .WithReportFolder("nbomber_reports/volume_test")
            .Run();
    }

    private string GetCredentialId()
    {
        var credentialIdBytes = new byte[20];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(credentialIdBytes);
        return credentialIdBytes.ToBase64Url();
    }
}