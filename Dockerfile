# syntax=docker/dockerfile:1
#
# Multi-stage build (plan task 48, T5, T14). Build and publish onto the full SDK image; ship onto a
# "noble-chiseled" runtime image, which has no shell, no package manager, and no utility beyond the .NET
# runtime itself — nothing left for whoever reaches the container to run. Base images are pinned by digest,
# not just tag, for the same reason .github/workflows pin actions to a commit rather than a tag: a tag is a
# mutable pointer, a digest is not (T14). .github/dependabot.yml keeps every digest here current.
#
# The final image has no writable state by design: the secret store is in-memory only (T5), Data Protection
# uses the ephemeral provider (no key ring on disk), and there is no VOLUME. It is meant to be run with
# `docker run --read-only` — nothing here needs to write to its own filesystem, so nothing is lost by refusing
# to let it.

FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS node

FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:2fa828c68761b1b8c23d7662dc134421b9d3b59fe1425fdbc80804e390cdb24d AS build

# The client bundle build (Client/package.json, plan task 21) needs Node. Copying the official image's
# /usr/local avoids provisioning an apt repository for a tool that never ships in the final image.
COPY --from=node /usr/local /usr/local

WORKDIR /src
COPY . .
RUN dotnet restore src/OneShot.Web/OneShot.Web.csproj --locked-mode
RUN dotnet publish src/OneShot.Web/OneShot.Web.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:9651fa59abcdf177c30392cb44a820605ca5d618429ab37acbf6e7c644510b02 AS final

WORKDIR /app
COPY --from=build /app/publish .

# The chiseled image's default user is already non-root, but that default belongs to the base image, not to
# this Dockerfile — set it explicitly so it stays true regardless of a future base image change (T5).
USER $APP_UID

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# No shell and no curl/wget on this image — that is the point — so the container health-checks itself with
# the --healthcheck switch (src/OneShot.Web/Api/HealthCheckProbe.cs): a plain HTTP GET against its own
# /healthz using nothing the chiseled image doesn't already ship.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["dotnet", "OneShot.Web.dll", "--healthcheck"]

ENTRYPOINT ["dotnet", "OneShot.Web.dll"]
