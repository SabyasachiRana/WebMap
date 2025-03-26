# Usage:
#    $ cd /opt
#    $ git clone https://github.com/SabyasachiRana/WebMap.git
#    $ cd WebMap/docker
#    $ docker build -t webmap:latest .
#    $ docker run -d -v /opt/WebMap/docker/xml:/opt/xml -p 8000:8000 webmap:latest
#
# Nmap Example:
#    $ nmap -sT -A -oX /tmp/myscan.xml 192.168.1.0/24
#    $ mv /tmp/myscan.xml /opt/WebMap/docker/xml
#
# Now you can point your browser to http://localhost:8000

FROM alpine:latest

ENV DEBIAN_FRONTEND noninteractive

RUN apk update && apk add --no-cache \
    python3 py3-pip curl wget wkhtmltopdf libressl-dev vim nmap tzdata

RUN mkdir /opt/xml && mkdir /opt/notes && \
    wget -P /opt/ https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz && \
    cd /opt/ && tar -xvf /opt/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz

RUN pip3 install Django requests xmldict && \
    cd /opt/ && django-admin startproject nmapdashboard && cd /opt/nmapdashboard && \
    git clone https://github.com/SabyasachiRana/WebMap.git nmapreport && \
    cd nmapreport && git checkout master

RUN cp /opt/nmapdashboard/nmapreport/docker/settings.py /opt/nmapdashboard/nmapdashboard/
RUN cp /opt/nmapdashboard/nmapreport/docker/urls.py /opt/nmapdashboard/nmapdashboard/
RUN cp /opt/nmapdashboard/nmapreport/docker/tzdata.sh /root/tzdata.sh
RUN cp /opt/nmapdashboard/nmapreport/docker/startup.sh /startup.sh

RUN cd /opt/nmapdashboard && python3 manage.py migrate
RUN ln -s /opt/nmapdashboard/nmapreport/token.py /root/token
RUN chmod +x /root/token

EXPOSE 8000

ENTRYPOINT ["sh", "/startup.sh"]
