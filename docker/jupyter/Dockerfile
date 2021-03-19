FROM pangeo/base-notebook:2020.11.06

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN apt-get update -y && \
	apt-get install -y \
		krb5-user \
		smbclient \
	&& apt-get clean all \
	&& find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

RUN pip3 install --upgrade --no-cache-dir \
        s3fs

RUN conda install -n notebook -c conda-forge -y \
	python-gssapi \
	smbprotocol \
        s3fs \
	&& conda clean -afy

USER $NB_UID
