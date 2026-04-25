using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NBomber.Contracts;
using NBomber.Contracts.Stats;
using NBomber.CSharp;
using Shark.Fido2.Common.Extensions;
using Shark.Fido2.Core.Abstractions;
using Shark.Fido2.InMemory;

namespace Shark.Fido2.Core.Performance.Tests;

[TestFixture]
[SuppressMessage("Major Code Smell", "S2699:Tests should include assertions", Justification = "Performance tests do not have assertions.")]
public class PerformanceTestScenarios
{
    private const string ReportsLocation = "nbomber_reports";

    private readonly ConcurrentBag<(string CredentialId, string Name)> _enduranceTestUsers = [];
    private readonly PerformanceTestHelper _performanceTestHelper = new();

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
    public void SpikePerformanceTests()
    {
        const string TestName = "spike";

        var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
        var assertion = _serviceProvider!.GetRequiredService<IAssertion>();

        var registrationScenario = GetAttestationScenario(attestation, TestName)
            .WithLoadSimulations(
                Simulation.Inject(rate: 2, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 10, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 2, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)));

        var authenticationScenario = GetAssertionScenario(assertion, TestName)
            .WithLoadSimulations(
                Simulation.Inject(rate: 10, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)),
                Simulation.Inject(rate: 10, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromSeconds(10)));

        NBomberRunner
            .RegisterScenarios(registrationScenario, authenticationScenario)
            .WithReportFolder($"{ReportsLocation}/{TestName}")
            .WithReportFormats(ReportFormat.Html)
            .Run();
    }

    [Test]
    public void StressPerformanceTests()
    {
        const string TestName = "stress";

        var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
        var assertion = _serviceProvider!.GetRequiredService<IAssertion>();

        var registrationScenario = GetAttestationScenario(attestation, TestName)
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 25, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(2)));

        var authenticationScenario = GetAssertionScenario(assertion, TestName)
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(2)));

        NBomberRunner
            .RegisterScenarios(registrationScenario, authenticationScenario)
            .WithReportFolder($"{ReportsLocation}/{TestName}")
            .WithReportFormats(ReportFormat.Html)
            .Run();
    }

    [Test]
    public void EndurancePerformanceTests()
    {
        const string TestName = "endurance";

        var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
        var assertion = _serviceProvider!.GetRequiredService<IAssertion>();

        var registrationScenario = GetAttestationScenario(attestation, TestName)
            .WithLoadSimulations(
                Simulation.Inject(rate: 2, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(5)));

        var authenticationScenario = GetAssertionScenario(assertion, TestName)
            .WithLoadSimulations(
                Simulation.Inject(rate: 10, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(5)));

        NBomberRunner
            .RegisterScenarios(registrationScenario, authenticationScenario)
            .WithReportFolder($"{ReportsLocation}/{TestName}")
            .WithReportFormats(ReportFormat.Html)
            .Run();
    }

    [Test]
    public void VolumePerformanceTests()
    {
        const string TestName = "volume";

        var attestation = _serviceProvider!.GetRequiredService<IAttestation>();
        var assertion = _serviceProvider!.GetRequiredService<IAssertion>();

        var registrationScenario = GetAttestationScenario(attestation, TestName)
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 50, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(3)));

        var authenticationScenario = GetAssertionScenario(assertion, TestName)
            .WithLoadSimulations(
                Simulation.RampingInject(rate: 200, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(3)));

        NBomberRunner
            .RegisterScenarios(registrationScenario, authenticationScenario)
            .WithReportFolder($"{ReportsLocation}/{TestName}")
            .WithReportFormats(ReportFormat.Html)
            .Run();
    }

    private ScenarioProps GetAttestationScenario(IAttestation attestation, string name)
    {
        var registrationScenario = Scenario
            .Create($"{name}_registration", async context =>
            {
                var request = _performanceTestHelper.GenerateRegistrationRequest();
                var result = await attestation.CompleteRegistration(
                    request.Attestation,
                    request.CreationOptions,
                    CancellationToken.None);

                _enduranceTestUsers.Add((request.CredentialId.ToBase64Url(), request.Username));

                return result != null && result.IsValid ? Response.Ok() : Response.Fail();
            });

        return registrationScenario;
    }

    private ScenarioProps GetAssertionScenario(IAssertion assertion, string name)
    {
        var authenticationScenario = Scenario
            .Create($"{name}_authentication", async context =>
            {
                if (_enduranceTestUsers.IsEmpty)
                {
                    return Response.Ok();
                }

                var (credentialId, name) = _enduranceTestUsers.ElementAt(
                    new Random().Next(0, _enduranceTestUsers.Count));
                var request = _performanceTestHelper.GenerateAuthenticationRequest(credentialId, name);
                var result = await assertion.CompleteAuthentication(
                    request.Assertion,
                    request.RequestOptions,
                    CancellationToken.None);

                return result != null && result.IsValid ? Response.Ok() : Response.Fail();
            });

        return authenticationScenario;
    }
}