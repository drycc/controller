FROM docker.io/library/python:3.9-alpine

COPY requirements.txt /app/requirements.txt

ENV PATH="/app/.venv/bin:${PATH}"

RUN apk add --update --virtual .build-deps \
    postgresql-dev \
    gcc \
    rust \
    cargo \
    libffi-dev \
    musl-dev \
    openssl-dev \
  && python3 -m venv /app/.venv \
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
