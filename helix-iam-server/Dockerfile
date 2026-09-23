# syntax=docker/dockerfile:1
# Multi-stage build for helix-iam-server (Spring Boot 3.5 / Java 21).
# Build context is this module directory: docker build -f helix-iam-server/Dockerfile helix-iam-server

########## Build stage ##########
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
# Warm the dependency cache first so source-only changes don't re-download the world.
COPY pom.xml ./
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -DskipTests dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -DskipTests clean package \
 && cp target/helix-iam-server-*.jar /build/app.jar

########## Runtime stage ##########
# Minimal JRE runtime (glibc, small). Non-root, read-only-root-FS compatible (writes only /tmp).
FROM eclipse-temurin:21-jre AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r helix && useradd -r -g helix -u 10001 -d /app helix
WORKDIR /app
COPY --from=build /build/app.jar /app/app.jar

# Container-aware heap, entropy source, temp dir under the (tmpfs) /tmp mount.
ENV SERVER_PORT=8080 \
    JAVA_OPTS="" \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/urandom -Djava.io.tmpdir=/tmp"

USER 10001
EXPOSE 8080

# Readiness probe via the actuator (health.probes.enabled=true in application.properties).
HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=20 \
  CMD curl -fsS "http://127.0.0.1:${SERVER_PORT}/actuator/health/readiness" || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
