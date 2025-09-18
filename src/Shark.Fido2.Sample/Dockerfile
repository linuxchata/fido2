FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
COPY ["Directory.Build.props", "/"]
COPY ["src/Shark.Fido2.Sample/Shark.Fido2.Sample.csproj", "Shark.Fido2.Sample/"]
COPY ["src/Shark.Fido2.Core/Shark.Fido2.Core.csproj", "Shark.Fido2.Core/"]
COPY ["src/Shark.Fido2.Common/Shark.Fido2.Common.csproj", "Shark.Fido2.Common/"]
COPY ["src/Shark.Fido2.Domain/Shark.Fido2.Domain.csproj", "Shark.Fido2.Domain/"]
COPY ["src/Shark.Fido2.Models/Shark.Fido2.Models.csproj", "Shark.Fido2.Models/"]
COPY ["src/Shark.Fido2.InMemory/Shark.Fido2.InMemory.csproj", "Shark.Fido2.InMemory/"]
RUN dotnet restore "Shark.Fido2.Sample/Shark.Fido2.Sample.csproj"
COPY . .
WORKDIR "/src/Shark.Fido2.Sample"
RUN dotnet build "./Shark.Fido2.Sample.csproj" -c "$BUILD_CONFIGURATION" -o /app/build

RUN rm -f appsettings.Production.json appsettings.Test.json || true

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Shark.Fido2.Sample.csproj" -c "$BUILD_CONFIGURATION" -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Shark.Fido2.Sample.dll"]