FROM python:3.10

RUN mkdir /app
COPY requirements.txt /app/requirements.txt
WORKDIR /app
RUN apt-get update \
 && pip install --upgrade pip \
 && pip install -U pip setuptools \
 && pip install -r requirements.txt
