FROM tomcat:11.0.14-jdk21

# Enable JVM remote debugging
ENV JPDA_ADDRESS=*:5005
ENV JPDA_TRANSPORT=dt_socket
ENV JPDA_SUSPEND=n
ENV JPDA_SERVER=y

# Remove default apps
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy your WAR into Tomcat
COPY target/spring-security-lab.war /usr/local/tomcat/webapps/ROOT.war

# Expose web port + debug port
EXPOSE 8080 5005

# Start Tomcat in JPDA (debug) mode
CMD ["catalina.sh", "jpda", "run"]
