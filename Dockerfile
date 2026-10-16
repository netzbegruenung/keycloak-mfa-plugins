# syntax=docker/dockerfile:1

# Builds the provider jars inside a container with a current JDK and Maven, and
# exports them to the host. Useful when the local JDK cannot reach Maven Central
# (e.g. a truststore without the ISRG roots behind repo.maven.apache.org).
#
#   docker build --platform linux/amd64 --output type=local,dest=dist .
#
# The result image contains nothing but the jars, so `--output` writes them
# straight to ./dist. Tests are skipped by default; pass
# `--build-arg SKIP_TESTS=false` to run them (several minutes, embedded Keycloak).

FROM --platform=$BUILDPLATFORM maven:3.9-eclipse-temurin-17 AS build

ARG SKIP_TESTS=true
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -DskipTests=${SKIP_TESTS} install \
    && mkdir /out \
    && cp sms-authenticator/target/netzbegruenung.*.jar \
          email-authenticator/target/netzbegruenung.*.jar \
          app-authenticator/target/netzbegruenung.*.jar \
          enforce-mfa/target/netzbegruenung.*.jar \
          trusted-device-authenticator/target/netzbegruenung.*.jar \
          /out/

FROM scratch AS jars
COPY --from=build /out/ /
