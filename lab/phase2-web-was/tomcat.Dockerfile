FROM tomcat:10.1.61-jdk21-temurin-noble
ARG LAB_STAGE=before
COPY before/server.xml /opt/lab/before.xml
COPY after/server.xml /opt/lab/after.xml
RUN test "$LAB_STAGE" = before -o "$LAB_STAGE" = after && cp /opt/lab/$LAB_STAGE.xml conf/server.xml && rm -rf webapps/* && mkdir -p webapps/lab && if [ "$LAB_STAGE" = before ]; then cp -r webapps.dist/docs webapps.dist/examples webapps/; fi
COPY health.jsp /usr/local/tomcat/webapps/lab/health.jsp
COPY Probe.java /opt/lab/Probe.java
RUN javac -encoding UTF-8 -d /opt/lab /opt/lab/Probe.java
COPY start-tomcat.sh /opt/lab/start.sh
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/opt/lab/start.sh"]
CMD ["catalina.sh", "run"]
