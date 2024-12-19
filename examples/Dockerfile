FROM ubuntu:latest AS build-stage

MAINTAINER example@example.com

COPY . .

ADD example.txt /app/example.txt

RUN apt-get update --insecurity=insecure

RUN echo "This RUN instruction should be after WORKDIR"

ENV PASSWORD=mysecretpassword

ARG password=mysecretpassword

HEALTHCHECK --interval=5m --timeout=3s CMD curl -u user:password http://localhost/ || exit 1

FROM ubuntu@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

WORKDIR /app
COPY --from=build-stage /app /app
