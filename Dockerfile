# syntax=docker/dockerfile:1

# ---------- build ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first (cached unless the csproj changes)
COPY *.csproj ./
RUN dotnet restore

# Then build + publish
COPY . .
RUN dotnet publish PersonalMcpVault.csproj -c Release -o /app --no-restore

# ---------- runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Non-root user (compose can override the UID/GID to match your vault's owner).
RUN adduser --disabled-password --gecos "" --uid 10001 appuser \
    && mkdir -p /data && chown appuser:appuser /data

COPY --from=build /app ./

ENV ASPNETCORE_URLS=http://0.0.0.0:5090 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    Auth__StorePath=/data/oauth-store.db

EXPOSE 5090
VOLUME ["/data"]
USER appuser

# `dotnet ... hash-password` still works: run  `docker compose run --rm vault-mcp hash-password`
ENTRYPOINT ["dotnet", "PersonalMcpVault.dll"]
