# re-based onto Debian testing for current krb5-1.18 for smbprotocol to work
# with gssproxy and also to match the container we're sidecar(e)ing to
FROM debian:testing
#FROM ubuntu:bionic
#FROM ubuntu:20.04

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root
RUN apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y gssproxy && \
        apt-get clean all && \
	find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

COPY entrypoint /
RUN chmod 755 /entrypoint

ENTRYPOINT ["/entrypoint", "-i"]
CMD ["--debug-level=1"]
