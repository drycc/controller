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
  && find /app/.venv /usr/local -type f -executable ! -path '*/cryptography*' -exec scanelf --needed --nobanner --format '%n#p' '{}' ';' \
    | tr ',' '\n' \
    | sort -u \
    | awk 'system("[[ -e /app/.venv/lib/" $1 " || -e /usr/local/lib/" $1 " ]]") == 0 { next } { print "so:" $1 }' \
    | xargs -rt apk add --no-cache --virtual .python-rundeps \
  && apk add --update --virtual .controller-rundeps \
    ca-certificates \
    su-exec \
    bash \
    shadow \
  && apk del .build-deps

COPY . /app


ENV PATH /app/.venv/bin:/app/bin:$PATH
WORKDIR /app
CMD ["/app/bin/boot"]
EXPOSE 8000
