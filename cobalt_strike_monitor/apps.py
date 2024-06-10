import os
import sys
from multiprocessing import Manager

from django.apps import AppConfig


class CobaltStrikeMonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cobalt_strike_monitor'

    def ready(self):
        from . import signals

        if 'runserver' not in sys.argv:
            # Exit quick if we're doing other Django commands
            return True

        if os.environ.get('RUN_MAIN'):
            # Only run in the main process, not the file monitoring process
            from .poll_team_server import TeamServerPoller
            TeamServerPoller().initialise()
