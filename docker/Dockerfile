# Elasticsearch with the plugin baked in.
#   docker build -f docker/Dockerfile -t elasticsearch-ingest-splunk-forwarders:9.5.4 .
ARG STACK_VERSION=9.5.4
FROM docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
ARG STACK_VERSION
COPY --chown=elasticsearch:root dist/ingest-splunk-forwarders-*-es${STACK_VERSION}.zip /tmp/ingest-splunk-forwarders.zip
RUN bin/elasticsearch-plugin install --batch file:///tmp/ingest-splunk-forwarders.zip \
    && rm /tmp/ingest-splunk-forwarders.zip
