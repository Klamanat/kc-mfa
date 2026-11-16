# build ได้ทั้งสอง service:  docker build --build-arg MODULE=mfa-service .   |   --build-arg MODULE=demo-backend
FROM maven:3.9-eclipse-temurin-17 AS build
ARG MODULE
WORKDIR /src
COPY pom.xml .
COPY mfa-service/pom.xml mfa-service/
COPY mfa-spring-boot-starter/pom.xml mfa-spring-boot-starter/
COPY demo-backend/pom.xml demo-backend/
COPY mfa-service/src mfa-service/src
COPY mfa-spring-boot-starter/src mfa-spring-boot-starter/src
COPY demo-backend/src demo-backend/src
RUN mvn -B -q -pl ${MODULE} -am -DskipTests package \
 && cp ${MODULE}/target/${MODULE}-*.jar /app.jar

FROM eclipse-temurin:17-jre
RUN useradd --system --uid 10001 app
USER app
COPY --from=build /app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
