from django.urls import path

from event_tracker.plugins import EventReportingPluginPoint
from markdown_reports import views


class MarkdownEventLogs(EventReportingPluginPoint):
    category = "Markdown"
    icon_class = "fas fa-list-ul"
    title = "Event Logs"
    name = "markdown-event-logs"
    view_class = views.MarkdownEventLogsView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]


class MarkdownIOCs(EventReportingPluginPoint):
    category = "Markdown"
    icon_class = "fa-solid fa-fingerprint"
    title = "Indicators of Compromise"
    name = "markdown-ioc-report"
    view_class = views.MarkdownIOCView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]


class MarkdownDetectionAdvice(EventReportingPluginPoint):
    category = "Markdown"
    icon_class = "fa-regular fa-hand-point-right"
    title = "Detection Advice"
    name = "markdown-detection-advice"
    view_class = views.MarkdownDetectionAdvice

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]
