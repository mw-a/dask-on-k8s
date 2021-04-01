# re-based onto Debian testing for current krb5-1.18 for smbprotocol to work
# with gssproxy and also to match the container we're sidecar(e)ing to
FROM debian:testing
#FROM ubuntu:bionic
#FROM ubuntu:20.04

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

# we need gssproxy 0.8.4 from unstable to avoid
# https://pagure.io/gssproxy/issue/256, can be removed as soon as gssproxy
# 0.8.4 makes it into testing or even stable
# unstable package has for some reason killed /var/lib/gssproxy - restore for
# now to avoid startup error about not being able to create default.sock
USER root
RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y gssproxy && \
	echo "deb http://deb.debian.org/debian unstable main" > /etc/apt/sources.list.d/unstable.list && \
	apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get -t unstable install -y gssproxy && \
	mkdir -p /var/lib/gssproxy && \
	apt-get clean all && \
	find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

COPY entrypoint /
RUN chmod 755 /entrypoint

ENTRYPOINT ["/entrypoint", "-i"]
CMD ["--debug-level=1"]
