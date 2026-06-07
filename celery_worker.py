"""Celery worker entry point for TrustSphere."""

from app import create_app
from app.tasks.celery_app import celery, make_celery


# Worker: celery -A celery_worker worker --loglevel=info --concurrency=4
# Beat: celery -A celery_worker beat --loglevel=info

flask_app = create_app("development")
make_celery(flask_app)
flask_app.app_context().push()

broker_url = celery.conf.broker_url
registered_tasks = [
    task_name
    for task_name in celery.tasks.keys()
    if task_name.startswith("trustsphere.tasks.")
]
redis_status = "eager synchronous mode" if celery.conf.task_always_eager else "broker mode"

print("")
print("TrustSphere Celery Worker")
print(f"Broker URL: {broker_url}")
print(f"Redis status: {redis_status}")
print(f"Registered TrustSphere tasks: {len(registered_tasks)}")
print("")
