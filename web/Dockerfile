# secrets-web: build on the host that will run it: `docker build -t secrets-web:local .`
# (Building locally keeps the image off shared CI runners that could tamper with it; see README "Security model".)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/SecretsWeb/SecretsWeb.csproj src/SecretsWeb/
RUN dotnet restore src/SecretsWeb/SecretsWeb.csproj
COPY src/ src/
RUN dotnet publish src/SecretsWeb/SecretsWeb.csproj -c Release -o /app --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends git age openssh-client \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
# git only honors safe.directory from protected scopes (system / global); values passed via `-c` or GIT_CONFIG_* are ignored.
# The bare repo at /repo is owned by the git server's uid while the container runs as 1654, so without this git reports
# "detected dubious ownership". ProcessRunner points GIT_CONFIG_GLOBAL here (the system file stays blocked by GIT_CONFIG_NOSYSTEM).
RUN printf '[safe]\n\tdirectory = /repo\n\tdirectory = /data/work\n' > /app/gitconfig
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    DOTNET_NOLOGO=1
EXPOSE 8080
# The official image ships a non-root user "app" (UID/GID 1654)
USER $APP_UID
ENTRYPOINT ["dotnet", "SecretsWeb.dll"]
