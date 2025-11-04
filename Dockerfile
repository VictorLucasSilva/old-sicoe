FROM python:3.13-alpine3.21

ENV PYTHONDONTWRITEBYTECODE=1

ENV PYTHONUNBUFFERED=1

COPY ./djangoapp /djangoapp
COPY ./scripts /scripts

WORKDIR /djangoapp

EXPOSE 8000

RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    postgresql-dev \
    openssl-dev \
    libxml2-dev \
    libxslt-dev \
    linux-headers \
    curl \
    jpeg-dev \
    zlib-dev

RUN python -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install -r /djangoapp/requirements.txt && \
    /venv/bin/pip install --upgrade setuptools wheel && \
    mkdir -p /data/web/static /data/web/media && \
    chmod -R +x /scripts/commands.sh 
# adduser --disabled-password --no-create-home victor && \
# chown -R victor:victor /venv && \
# chown -R victor:victor /data/web/static && \
# chown -R victor:victor /data/web/media && \
# chmod -R 755 /data/web/static /data/web/media && \

ENV PATH="/scripts:/venv/bin:$PATH"

CMD ["/bin/sh", "/scripts/commands.sh"]
