FROM amazoncorretto:19-alpine-jdk
VOLUME /tmp
ARG JAR_FILE
ARG AGENT_ARG
ENV AGENT_ENV=${AGENT_ARG}
ARG NEWSGEARS_DEVELOPMENT
ARG NEWSGEARS_SINGLEUSERMODE
ARG NEWSGEARS_ORIGINURL
ARG SPRING_DATASOURCE_URL
ARG SPRING_DATASOURCE_USERNAME
ARG SPRING_DATASOURCE_PASSWORD
ARG TOKEN_SERVICE_SECRET
ARG BROKERCLAIM_API
COPY ${JAR_FILE} app.jar
ENV NEWSGEARS_DEVELOPMENT false
ENV NEWSGEARS_SINGLEUSERMODE ${NEWSGEARS_SINGLEUSERMODE}
ENV NEWSGEARS_ORIGINURL ${NEWSGEARS_ORIGINURL}
ENV SPRING_DATASOURCE_URL jdbc:postgresql://feedgears-db01:5432/postgres
ENV SPRING_DATASOURCE_USERNAME postgres
ENV SPRING_DATASOURCE_PASSWORD postgres
ENV TOKEN_SERVICE_SECRET ${TOKEN_SERVICE_SECRET}
ENV BROKERCLAIM_API ${BROKERCLAIM_API}
ENTRYPOINT java ${AGENT_ENV} -Djava.security.egd=file:/dev/./urandom -jar /app.jar
