from django.urls import path

from event_tracker.plugins import EventReportingPluginPoint
from external_tool_reports import views


class OfficeTimelineExport(EventReportingPluginPoint):
    category = "External Tools"
    icon_class = "fa-solid fa-chart-gantt"
    title = "Office Timeline Export"
    name = "office-timeline-export"
    view_class = views.OfficeTimelineExportOptions

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
        path("<int:task_id>/report/generate", views.OfficeTimelineExportGenerate.as_view(), name="office-timeline-export-generate"),
    ]


class MITREAttackNavigator(EventReportingPluginPoint):
    category = "External Tools"
    icon_class = "fa-solid fa-compass"
    title = "MITRE ATT&CK Navigator"
    name = "mitre-attack-navigator"
    view_class = views.MITREAttackNavigatorView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]

