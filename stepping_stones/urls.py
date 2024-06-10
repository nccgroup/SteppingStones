"""stepping_stones URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, reverse_lazy
from django.views.generic import RedirectView
from djangoplugins.utils import include_plugins

from event_tracker.models import Task
from event_tracker.plugins import EventReportingPluginPoint, CredentialReportingPluginPoint


def root_view(request):
    """
    Callable to ensure Task.objects is queried for each request
    """
    return RedirectView.as_view(
        url=reverse_lazy('event_tracker:event-list', kwargs={"task_id": Task.objects.last().pk}))(request)


urlpatterns = [
    path('', root_view),
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
    path("event-tracker/", include("event_tracker.urls")),
    path('taggit/', include('taggit_bulk.urls')),
    path('plugins/events-reports/', include_plugins(EventReportingPluginPoint)),
    path('plugins/cred-reports/', include_plugins(CredentialReportingPluginPoint)),
]
