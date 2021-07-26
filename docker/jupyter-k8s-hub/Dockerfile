FROM jupyterhub/k8s-hub:1.0.1

LABEL maintainer="Michael Weiser <michael.weiser@atos.net>"

USER root

RUN pip3 install --upgrade --no-cache-dir \
        boto3

USER jovyan
