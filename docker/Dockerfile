FROM python:3-slim

ARG BUILDPLATFORM TARGETPLATFORM TARGETOS TARGETARCH

# Set python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENV DEBIAN_FRONTEND=noninteractive

ENV WKHTMLTOX_VERSION=0.12.6.1-3

WORKDIR /opt

RUN apt-get update && apt-get install -y libssl3t64 vim nmap wget

RUN echo "Building for ${TARGETPLATFORM} OS: ${TARGETOS} ARCH: ${TARGETARCH} VARIANT: ${TARGETVARIANT}"
ARG WKHTML_PACK=wkhtmltox_${WKHTMLTOX_VERSION}.bookworm_${TARGETARCH}.deb
RUN wget -P . https://github.com/wkhtmltopdf/packaging/releases/download/${WKHTMLTOX_VERSION}/${WKHTML_PACK} && \
    apt-get install -y --no-install-recommends --no-install-suggests ./${WKHTML_PACK} && \
    rm -f ${WKHTML_PACK} && \
    apt-get autoremove -y

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    django-admin startproject nmapdashboard

COPY --exclude=.github --exclude=docker . /opt/nmapdashboard/nmapreport
RUN wget -P nmapdashboard/nmapreport/nmap/nse https://raw.githubusercontent.com/vulnerability-lookup/vulnerability-lookup/refs/heads/main/tools/vulnerability-lookup.nse

COPY docker/settings.py docker/urls.py /opt/nmapdashboard/nmapdashboard
COPY docker/tzdata.sh /root/tzdata.sh
COPY docker/startup.sh /startup.sh

RUN mkdir /opt/xml /opt/notes && \
    cd /opt/nmapdashboard && \
    python3 manage.py migrate && \
    ln -s /opt/nmapdashboard/nmapreport/guitoken.py /root/token && \
    chmod +x /root/token

EXPOSE 8000

ENTRYPOINT ["bash", "/startup.sh"]
