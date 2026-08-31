# Multi-Stage Build for ULPF Spring Boot Middleware
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder

WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# Production Runtime Stage
FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache curl tzdata \
    && addgroup -S ulpf && adduser -S ulpf -G ulpf

WORKDIR /app
COPY --from=builder /build/target/ulpf-backend-1.0.0.jar /app/ulpf-backend.jar

USER ulpf:ulpf

EXPOSE 8080 1514/udp 1514/tcp

ENV SPRING_PROFILES_ACTIVE=docker \
    JAVA_OPTS="-Xms512m -Xmx1024m -XX:+UseG1GC"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/ulpf-backend.jar"]
