from django.urls import path

from event_tracker.plugins import EventReportingPluginPoint
from graphical_reports import views


class GraphicalMitreEventTimeline(EventReportingPluginPoint):
    category = "Images"
    icon_class = "fas fa-stream"
    title = "MITRE Event Timeline"
    name = "graphical-mitre-event-timeline"
    view_class = views.GraphicalMitreEventTimelineView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]


class GraphicalDailyDetectionsAndPreventions(EventReportingPluginPoint):
    category = "Images"
    icon_class = "fa-solid fa-chart-column"
    title = "Daily Detections and Preventions"
    name = "graphical-daily-detections-and-preventions"
    view_class = views.GraphicalDailyDetectionsAndPreventionsView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
    ]


class GraphicalMitreHeatMap(EventReportingPluginPoint):
    category = "Images"
    icon_class = "fas fa-border-all"
    title = "MITRE Heat Map"
    name = "graphical-mitre-heat-map"
    view_class = views.GraphicalMitreHeatMapEventListView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
        path("<int:task_id>/report/<str:include_subtechniques>", views.GraphicalMitreHeatMapEventListView.as_view(), name=f"heat-map-with-options"),
    ]
