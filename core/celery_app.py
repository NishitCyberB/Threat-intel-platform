from celery import Celery

celery = Celery(
    "threat_tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

# 🔥 IMPORTANT: include tasks
celery.conf.update(
    include=["core.tasks"],

    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
