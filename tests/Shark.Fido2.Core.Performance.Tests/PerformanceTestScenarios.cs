using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NBomber.Contracts.Stats;
using NBomber.CSharp;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.InMemory;
using Shark.Fido2.Tests.Common.DataReaders;

namespace Shark.Fido2.Core.Performance.Tests;

public class PerformanceTestScenarios
{
    private const string NoneAttestation = "NoneAttestation.json";
    private const string NoneCreationOptions = "NoneCreationOptions.json";
    private const string NoneAssertion = "NoneAssertion.json";
    private const string NoneRequestOptions = "NoneRequestOptions.json";

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
        var registrationScenario = Scenario
            .Create("endurance_registration", async context =>
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
                Simulation.Inject(rate: 2, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(5)));

        var authenticationScenario = Scenario
            .Create("endurance_authentication", async context =>
            {
                var assertion = _serviceProvider!.GetRequiredService<IAssertion>();
                var attestation = _serviceProvider!.GetRequiredService<IAttestation>();

                // Register first
                var attestationData = DataReader.ReadAttestationData(NoneAttestation);
                var creationOptions = DataReader.ReadCreationOptions(NoneCreationOptions);
                await attestation.CompleteRegistration(attestationData, creationOptions, CancellationToken.None);

                // Then authenticate
                var assertionData = DataReader.ReadAssertionData(NoneAssertion);
                var requestOptions = DataReader.ReadRequestOptions(NoneRequestOptions);

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
            .WithReportFormats(ReportFormat.Html, ReportFormat.Csv, ReportFormat.Md)
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
}