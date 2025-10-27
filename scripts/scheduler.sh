#!/bin/sh
set -e

while ! nc -z "$POSTGRES_HOST" "$POSTGRES_PORT"; do
  echo "🟡 Waiting for Postgres ($POSTGRES_HOST:$POSTGRES_PORT) ..."
  sleep 2
done
echo "✅ Postgres up ($POSTGRES_HOST:$POSTGRES_PORT)"

/venv/bin/python manage.py migrate --noinput
/venv/bin/python manage.py runscheduler
