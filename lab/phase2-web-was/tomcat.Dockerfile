FROM tomcat:10.1.61-jdk21-temurin-noble
ARG LAB_STAGE=before
COPY before/server.xml /opt/lab/before.xml
COPY after/server.xml /opt/lab/after.xml
RUN test "$LAB_STAGE" = before -o "$LAB_STAGE" = after && cp /opt/lab/$LAB_STAGE.xml conf/server.xml && rm -rf webapps/* && mkdir -p webapps/lab && if [ "$LAB_STAGE" = before ]; then cp -r webapps.dist/docs webapps.dist/examples webapps/; fi
COPY health.jsp /usr/local/tomcat/webapps/lab/health.jsp
RUN mkdir -p webapps/lab/files webapps/lab/WEB-INF && printf 'LAB_DIRECTORY_CANARY\n' > webapps/lab/files/example.txt && if [ "$LAB_STAGE" = before ]; then listing=true; printf 'LAB_SAMPLE_BACKUP\n' > webapps/lab/files/sample.bak; else listing=false; rm -rf webapps.dist; fi && printf '<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee" version="6.0"><servlet><servlet-name>default</servlet-name><servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class><init-param><param-name>listings</param-name><param-value>%s</param-value></init-param></servlet><servlet-mapping><servlet-name>default</servlet-name><url-pattern>/</url-pattern></servlet-mapping></web-app>\n' "$listing" > webapps/lab/WEB-INF/web.xml
COPY Probe.java /opt/lab/Probe.java
COPY SelectedProbe.java /opt/lab/SelectedProbe.java
RUN javac -encoding UTF-8 -d /opt/lab /opt/lab/Probe.java /opt/lab/SelectedProbe.java
COPY start-tomcat.sh /opt/lab/start.sh
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/opt/lab/start.sh"]
CMD ["catalina.sh", "run"]
