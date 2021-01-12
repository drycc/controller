FROM docker.io/library/python:3.8-alpine

COPY requirements.txt /app/requirements.txt

RUN apk add --update --virtual .build-deps \
    postgresql-dev \
    gcc \
    libffi-dev \
    musl-dev \
    openldap-dev \
  && pip3 install --disable-pip-version-check --no-cache-dir -r /app/requirements.txt \
  && runDeps="$( \
    scanelf --needed --nobanner --format '%n#p' --recursive /usr/local \
    | tr ',' '\n' \
    | sort -u \
    | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
    )" \
  && apk add --update --virtual .controller-rundeps \
    $runDeps \
    ca-certificates \
    su-exec \
    bash \
    shadow \
  && apk del .build-deps

COPY . /app

WORKDIR /app
CMD ["/app/bin/boot"]
EXPOSE 8000
