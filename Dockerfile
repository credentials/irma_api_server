FROM tomcat:8-jre8

# Set config dir
ENV IRMA_API_CONF "/etc/irma_api_conf"

# Create container
RUN rm -r /usr/local/tomcat/webapps/

COPY docker/ /etc/irma_api_conf/
COPY ./build/libs/irma_api_server.war /usr/local/tomcat/webapps/ROOT.war
