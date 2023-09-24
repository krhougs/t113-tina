FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update

# WORKDIR /tmp
# RUN openssl version

# RUN apt-get install build-essential wget
RUN apt-get install sudo wget build-essential subversion git-core libncurses5-dev zlib1g-dev gawk flex quilt xsltproc libxml-parser-perl mercurial bzr ecj cvs unzip lib32z1 lib32z1-dev lib32stdc++6 libstdc++6 libmpc-dev libgmp-dev -y
RUN apt-get install bc busybox rsync xxd ca-certificates -y
# # RUN apt-get -y remove openssl* libssl*

RUN apt-get install -y libssl1.0 libssl1.0-dev openssl1.0
# RUN mv /usr/lib/ssl /usr/lib/ssl1.1
# RUN ln -s /usr/lib/ssl1.0 /usr/lib/ssl

ARG UID=1000
ARG GID=1000

RUN groupadd -g "${GID}" builder \
  && useradd --create-home --no-log-init -u "${UID}" -g "${GID}" builder
RUN echo "builder:builder" | chpasswd
USER builder

# ENV OPENSSL_DIR=/usr/lib/ssl1.0/
WORKDIR /app
