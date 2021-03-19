FROM daskgateway/dask-gateway:0.9.0

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN apt-get update -y && \
	apt-get install -y \
		gcc \
		libkrb5-dev \
		krb5-user \
	&& apt-get clean all \
	&& find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

RUN pip install --upgrade --no-cache-dir \
	smbprotocol\[kerberos\] \
        s3fs

#RUN conda install -y conda-build && \
#	conda clean -afy

#RUN conda skeleton pypi pyspnego gssapi smbprotocol && \
#	conda build --no-test pyspnego gssapi smbprotocol && \
#	conda install -y --use-local gssapi smbprotocol && \
#	conda clean -afy && \
#	rm -rf /opt/conda/conda-bld

RUN conda install -c conda-forge -y \
	python-gssapi \
	smbprotocol \
        s3fs \
	&& conda clean -afy

USER $NB_UID
