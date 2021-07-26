#FROM daskgateway/dask-gateway:0.9.0
# re-based onto Debian testing for current krb5-1.18 for smbprotocol to work
# with gssproxy
FROM mwa4/dask-gateway-dask:1

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN apt-get update -y && \
	apt-get install -y \
		gssproxy \
		gcc \
		libkrb5-dev \
		krb5-user \
	&& apt-get clean all \
	&& find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

# for debugging
#		smbclient \
#		vim \
#		krb5-user \

#RUN echo jovyan ALL=\(ALL:ALL\) NOPASSWD: ALL > /etc/sudoers.d/jovyan

# build gssapi from pypi because anaconda and conda-forge packages pull in a
# conda-specific krb5 package which does not yet provide the inquire_by_oid
# gssapi call required by pygssapi for use with gssproxy
RUN conda install -y conda-build && \
	conda skeleton pypi gssapi && \
	conda build --no-test gssapi && \
	conda install -c file:///opt/conda/conda-bld -y gssapi && \
	conda install -c conda-forge -y \
		smbprotocol \
		s3fs \
	&& \
	conda clean -afy && \
	rm -rf /opt/conda/conda-bld

# explicit gss_acquire_cred even on the default identity breaks
# gss_init_sec_context final iteration with
# "gssapi.raw.exceptions.InvalidCredentialsError: Major (655360): Invalid
# credential was supplied, Minor (100004): Unknown error"
RUN sed -i -e "/^def _get_gssapi_credential/a \\    return None" \
	/opt/conda/lib/python3.8/site-packages/spnego/gss.py

# match package versions of numpy, dask and distributed with
# pangeo/base-notebook
RUN conda install -c conda-forge -y \
		path \
		asammdf \
		holoviews \
		prefect \
		dask-jobqueue \
		scipy \
		numpy==1.20.3 \
		dask==2021.6.0 \
		distributed==2021.6.0 \
		&& \
	conda clean -afy

USER 1000:1000
