FROM daskgateway/dask-gateway:0.9.0

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN pip install --upgrade --no-cache-dir \
        s3fs

RUN conda install -y \
        s3fs \
	&& conda clean -afy

USER $NB_UID
