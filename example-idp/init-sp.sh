#!/bin/sh
set -e

echo "Running migrations..."
python manage.py migrate --noinput

echo "Setting Django Site domain to localhost:8443..."
python manage.py shell -c "
from django.contrib.sites.models import Site
Site.objects.update_or_create(id=1, defaults={'domain': 'localhost:8443', 'name': 'localhost'})
print('Site updated successfully')
"

echo "Starting gunicorn with TLS on port 8443..."
exec gunicorn blogproject.wsgi:application \
    --certfile=/app/certs/cert.pem \
    --keyfile=/app/certs/key.pem \
    --bind 0.0.0.0:8443 \
    --workers 2 \
    --access-logfile -
