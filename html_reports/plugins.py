from django.urls import path

from event_tracker.plugins import EventReportingPluginPoint
from html_reports import views


class HTMLEventLogs(EventReportingPluginPoint):
    category = "HTML"
    icon_class = "fas fa-list-ul"
    title = "Event Logs"
    name = "html-event-logs"
    view_class = views.HTMLEventLogsView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]


class HTMLMitreDetectionSummary(EventReportingPluginPoint):
    category = "HTML"
    icon_class = "fa-solid fa-traffic-light"
    title = "Detection Summary"
    name = "html-dection-summary"
    view_class = views.HTMLMitreDetectionSummaryView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]
