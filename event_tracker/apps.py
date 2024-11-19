import os
import sys
from datetime import timedelta

from django.apps import AppConfig
from django.utils import timezone


class EventTrackerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'event_tracker'

    def ready(self):
        # Need to import these so that background_tasks lib can find the decorated functions when it runs in its own
        # process. The alternative is to declare the tasks in tasks.py.
        from . import signals
        from . import background_tasks

        if 'runserver' not in sys.argv:
            # Exit quick if we're doing other Django commands
            return True

        if os.environ.get('RUN_MAIN'):
            # Only run in the main process, not the file monitoring process

            from event_tracker.background_tasks import sync_disabled_users, sync_bh_owned, sync_pwnedpasswords
            from background_task.models import Task
            from event_tracker.plugins import BackgroundTaskPluginPoint

            # Remove other sync_disabled_user tasks, there should only ever be one
            Task.objects.filter(task_name="event_tracker.background_tasks.sync_disabled_users").delete()
            sync_disabled_users(schedule=timezone.now(), repeat=180)  # Run every 3 minutes

            Task.objects.filter(task_name="event_tracker.background_tasks.sync_bh_owned").delete()
            sync_bh_owned(schedule=timezone.now() + timedelta(seconds=60), repeat=180)  # Run every 3 minutes, offset by 1 mins to allow sync_disabled_user to complete

            Task.objects.filter(task_name="event_tracker.background_tasks.sync_pwnedpasswords").delete()
            sync_pwnedpasswords(schedule=timezone.now() + timedelta(seconds=120), repeat=180)  # Run every 3 minutes, offset by 2 mins to allow sync_disabled_user to complete

            for eventsourcebackgroundtaskplugin in BackgroundTaskPluginPoint.get_plugins():
                if eventsourcebackgroundtaskplugin.is_active():
                    eventsourcebackgroundtaskplugin.schedule_function(schedule=eventsourcebackgroundtaskplugin.delay_seconds,
                                                             repeat=eventsourcebackgroundtaskplugin.repeat_seconds,
                                                             remove_existing_tasks=eventsourcebackgroundtaskplugin.replace_existing_tasks)


