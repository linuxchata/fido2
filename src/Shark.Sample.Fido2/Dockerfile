FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
COPY ["src/Shark.Sample.Fido2/Shark.Sample.Fido2.csproj", "Shark.Sample.Fido2/"]
COPY ["src/Shark.Fido2.Core/Shark.Fido2.Core.csproj", "Shark.Fido2.Core/"]
COPY ["src/Shark.Fido2.Common/Shark.Fido2.Common.csproj", "Shark.Fido2.Common/"]
COPY ["src/Shark.Fido2.Domain/Shark.Fido2.Domain.csproj", "Shark.Fido2.Domain/"]
COPY ["src/Shark.Fido2.Models/Shark.Fido2.Models.csproj", "Shark.Fido2.Models/"]
COPY ["src/Shark.Fido2.Repositories.InMemory/Shark.Fido2.Repositories.InMemory.csproj", "Shark.Fido2.Repositories.InMemory/"]
RUN ls
RUN dotnet restore "Shark.Sample.Fido2/Shark.Sample.Fido2.csproj"
COPY . .
WORKDIR "/src/Shark.Sample.Fido2"
RUN dotnet build "./Shark.Sample.Fido2.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Shark.Sample.Fido2.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Shark.Sample.Fido2.dll"]