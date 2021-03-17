FROM pangeo/base-notebook:2020.11.06

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN pip3 install --upgrade --no-cache-dir \
        s3fs

RUN conda install -n notebook -y \
        s3fs \
	&& conda clean -afy

USER $NB_UID
