#FROM pangeo/base-notebook:2020.11.06
#FROM pangeo/base-notebook:2021.03.19
# re-based onto Debian testing for current krb5-1.18 for smbprotocol to work
# with gssproxy
FROM mwa4/base-notebook-pangeo:1

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN apt-get update -y && \
	apt-get install -y \
		gssproxy \
		gcc \
		python3-dev \
		libkrb5-dev \
	&& apt-get clean all \
	&& find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

# for debugging
#		krb5-user \
#		smbclient \
#		vim \
#		sudo \

#RUN echo jovyan ALL=\(ALL:ALL\) NOPASSWD: ALL > /etc/sudoers.d/jovyan

# build gssapi from pypi because anaconda and conda-forge packages pull in a
# conda-specific krb5 package which does not yet provide the inquire_by_oid
# gssapi call required by pygssapi for use with gssproxy
# with krb5-less rebuild of curl so we can uninstall the conda krb5 altogether
# so it does not pollute our gssapi environment
RUN conda install -y conda-build && \
	mkdir -p /b && cd /b && \
	curlurl=https://raw.githubusercontent.com/conda-forge/curl-feedstock/cd26f1b178f1f0acc4327e59504848f1d67f5eec/recipe && \
	wget -O - $curlurl/meta.yaml | grep -v krb5 > meta.yaml && \
	wget -O - $curlurl/build.sh | sed -e "/--with-gssapi/s/--with.*/--without-gssapi \\\\/" > build.sh && \
	conda build --no-test .	&& \
	cd / && rm -rf /b && \
	conda install -c file:///srv/conda/conda-bld -y libcurl && \
	conda install -n notebook -c file:///srv/conda/conda-bld -y libcurl && \
	conda uninstall -y krb5 && \
	conda uninstall -n notebook -y krb5 && \
	conda skeleton pypi gssapi && \
	conda build --no-test gssapi && \
	conda install -n notebook -c file:///srv/conda/conda-bld -y gssapi && \
	conda install -n notebook -c conda-forge -y \
		smbprotocol \
		s3fs \
	&& \
	conda clean -afy && \
	rm -rf /srv/conda/conda-bld

# explicit gss_acquire_cred even on the default identity breaks
# gss_init_sec_context final iteration with
# "gssapi.raw.exceptions.InvalidCredentialsError: Major (655360): Invalid
# credential was supplied, Minor (100004): Unknown error"
RUN sed -i -e "/^def _get_gssapi_credential/a \\    return None" \
	/srv/conda/envs/notebook/lib/python3.8/site-packages/spnego/gss.py

RUN conda install -n notebook -c conda-forge -y \
		path \
		asammdf \
		holoviews \
		prefect \
		dask-jobqueue \
		scipy \
		&& \
	conda clean -afy

# pysmb
RUN conda install -n notebook -c conda-forge -y \
		pysmb \
		&& \
	conda clean -afy

# pysmbc
RUN apt-get update -y && \
	apt-get install -y libsmbclient-dev pkg-config && \
	conda skeleton pypi pysmbc && \
	conda build --no-test pysmbc && \
	conda install -n notebook -c file:///srv/conda/conda-bld -y pysmbc && \
	conda install -n notebook -c conda-forge -y pysmbc && \
	conda clean -afy && \
	rm -rf /srv/conda/conda-bld && \
	apt-get clean all && \
	find /var/cache/apt/archives /var/lib/apt/lists -type f -delete

USER $NB_UID
