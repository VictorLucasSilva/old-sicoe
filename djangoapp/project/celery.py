from __future__ import absolute_import, unicode_literals 
import os
from celery import Celery
from celery.schedules import crontab

settings_module = os.getenv('DJANGO_SETTINGS_MODULE')
settings_conf = os.getenv('DJANGO_SETTINGS_CONF')

if not settings_module:
    raise ValueError("A variável de ambiente 'DJANGO_SETTINGS_MODULE' não foi definida.")

os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

app = Celery('project')

app.config_from_object(settings_conf, namespace='CELERY')

app.autodiscover_tasks()

app.conf.beat_schedule = {
    'establishment_list_task': {
        'task': 'core.tasks.establishment_list',
        'schedule': crontab(minute='*/1'),
    },
    'update_status_attachment_task': {
        'task': 'core.tasks.update_status_attachment',
        'schedule': crontab(minute='*/30'),
    },
    'send_emails_to_users_task': {
        'task': 'core.tasks.send_emails_to_users',
        'schedule': crontab(minute='*/30'),
    },
    'update_status_user_task': {
        'task': 'core.tasks.update_status_user',
        'schedule': crontab(minute='*/30'),
    }
}

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
