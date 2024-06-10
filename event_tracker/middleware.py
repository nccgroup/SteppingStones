from django.contrib.auth import get_user
from django.contrib.auth.models import AnonymousUser, User
from django.core.management import execute_from_command_line
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.conf import settings
import os

from event_tracker.fixtures import gen_mitre_fixture
from event_tracker.models import UserPreferences, Task, AttackTactic


class TimezoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        user = get_user(request)
        if isinstance(user, AnonymousUser):
            timezone.deactivate()
        else:
            preferences = UserPreferences.objects.filter(user=user).first()
            if preferences and preferences.timezone:
                timezone.activate(preferences.timezone)
            else:
                timezone.deactivate()

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response


class InitialConfigMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        if not Task.objects.exists():
            if request.path != reverse('event_tracker:initial-config-task'):
                return redirect(reverse('event_tracker:initial-config-task'))
        elif not User.objects.exists():
            if request.path != reverse('event_tracker:initial-config-admin'):
                return redirect(reverse('event_tracker:initial-config-admin'))
        elif not AttackTactic.objects.exists():
            old_dir = os.getcwd()
            os.chdir(settings.BASE_DIR / "event_tracker/fixtures")
            gen_mitre_fixture.fetch_and_create()
            os.chdir(old_dir)
            execute_from_command_line(['manage.py', 'loaddata', 'event_tracker/fixtures/mitre-fixture.json'])

        response = self.get_response(request)

        return response