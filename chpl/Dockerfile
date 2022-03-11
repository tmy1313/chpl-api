# syntax=docker/dockerfile:1

FROM ubuntu:18.04
FROM openjdk:17

ENV VERSION=8.5.76
RUN cd /tmp
RUN curl -O http://apache.mirrors.lucidnetworks.net/tomcat/tomcat-8/v$VERSION/bin/apache-tomcat-$VERSION.tar.gz
RUN mkdir /opt/tomcat8/
#RUN mkdir /opt/tomcat8/apache-tomcat-$VERSION
RUN tar xzvf apache-tomcat-$VERSION.tar.gz -C /opt/tomcat8 --strip-components=1
RUN rm apache-tomcat-$VERSION.tar.gz


WORKDIR /opt/tomcat8/webapps

COPY index.html /opt/tomcat8/webapps/ROOT/index.html

RUN java -version


EXPOSE 8080

CMD ["/opt/tomcat8/bin/catalina.sh", "run"]