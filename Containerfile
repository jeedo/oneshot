# syntax=docker/dockerfile:1
#
# Two-stage build (plan task 48, T5, T14): a build stage on the full SDK image, and a "noble-chiseled" final
# runtime stage with no shell, no package manager, and no utility beyond the .NET runtime itself — nothing
# left for whoever reaches the container to run. Base images are pinned by digest, not just tag, for the same
# reason .github/workflows pin actions to a commit rather than a tag: a tag is a mutable pointer, a digest is
# not (T14). .github/dependabot.yml keeps both current.
#
# The final image has no writable state by design: the secret store is in-memory only (T5), Data Protection
# uses the ephemeral provider (no key ring on disk), and there is no VOLUME. It is meant to be run with
# `docker run --read-only` (a tmpfs /tmp covers whatever transient scratch space the runtime wants) — nothing
# here needs to write to its own filesystem, so nothing is lost by refusing to let it.

FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:35d40304542c8689331f8cab17c65926cdf48fe711e289321d71924b230a7d29 AS build

# The client bundle build (Client/package.json, plan task 21) needs Node, which the SDK image does not ship.
# The signing key is fetched and verified by checksum rather than piped into a shell — the same reasoning
# security.yml fetches gitleaks by checksum instead of trusting a moving action or tag.
ARG NODE_MAJOR=22
ARG NODE_PACKAGE_VERSION=22.23.2-1nodesource1
ARG NODESOURCE_ASC_SHA256=b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /tmp/nodesource.asc \
    && printf '%s  /tmp/nodesource.asc\n' "${NODESOURCE_ASC_SHA256}" > /tmp/nodesource.sha256 \
    && sha256sum --check --strict /tmp/nodesource.sha256 \
    && mkdir -p /etc/apt/keyrings \
    && gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg /tmp/nodesource.asc \
    && rm /tmp/nodesource.asc /tmp/nodesource.sha256 \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs=${NODE_PACKAGE_VERSION} \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN dotnet restore src/OneShot.Web/OneShot.Web.csproj --locked-mode
RUN dotnet publish src/OneShot.Web/OneShot.Web.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    -p:DebugType=none

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:48e51f2f6798897be7ac4e775c049ed8fe60d3190f637e1f9c9dc7513efa659c AS final

WORKDIR /app
COPY --from=build /app/publish .

# The chiseled image's default user is already non-root, but that default belongs to the base image, not to
# this Containerfile — set it explicitly so it stays true regardless of a future base image change (T5).
USER $APP_UID

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# No shell and no curl/wget on this image — that is the point — so the container health-checks itself with
# the --healthcheck switch (src/OneShot.Web/Api/HealthCheckProbe.cs): a plain HTTP GET against its own
# /healthz using nothing the chiseled image doesn't already ship.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["dotnet", "OneShot.Web.dll", "--healthcheck"]

ENTRYPOINT ["dotnet", "OneShot.Web.dll"]
