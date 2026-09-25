from __future__ import absolute_import
import os
from celery import Celery
from django.conf import settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'kamerka.settings')
app = Celery('kamerka')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
# namespace='CELERY' means all celery-related configuration keys in
# settings.py must be uppercase and prefixed with `CELERY_` (Celery 5's
# expected form), e.g. CELERY_BROKER_URL instead of the old BROKER_URL.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
