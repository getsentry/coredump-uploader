FROM ubuntu:latest

RUN apt-get update && apt-get install \
	gcc \
	gdb \
	elfutils \
	python-pip -y && pip install sentry-sdk && ulimit -c unlimited && mkdir coredump-uploader && pip install click
