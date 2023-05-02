FROM mcr.microsoft.com/dotnet/sdk:7.0-bullseye-slim AS base

WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:7.0-bullseye-slim AS build

COPY ["aspnetapp/", "/src/"]

WORKDIR /src
RUN dotnet restore "aspnetapp.csproj" && \
    dotnet publish "aspnetapp.csproj" --no-restore -c Release -o /app/publish

FROM base AS final
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "aspnetapp.dll"]