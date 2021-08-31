FROM docker.io/library/python:3.9-alpine

COPY requirements.txt /app/requirements.txt

RUN apk add --update --virtual .build-deps \
    gcc \
    rust \
    cargo \
    postgresql-dev \
    libffi-dev \
    musl-dev \
    openssl-dev \
  && python3 -m venv /app/.venv \
  && source /app/.venv/bin/activate \
  && pip3 install --disable-pip-version-check --no-cache-dir -r /app/requirements.txt \
  && runDeps="$( \
    scanelf --needed --nobanner --format '%n#p' --recursive /app/.venv \
    | tr ',' '\n' \
    | sort -u \
    | awk 'system("[ -e /app/.venv/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
    )" \
  && apk add --update --virtual .controller-rundeps \
    $runDeps \
    ca-certificates \
    su-exec \
    bash \
    shadow \
  && apk del .build-deps

COPY . /app

ENTRYPOINT ["/app/bin/entrypoint"]

WORKDIR /app
CMD ["/app/bin/boot"]
EXPOSE 8000
