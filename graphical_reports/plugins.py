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


class GraphicalMitreActivityHeatMap(EventReportingPluginPoint):
    category = "Images"
    icon_class = "fas fa-border-all"
    title = "Activity MITRE Heatmap"
    name = "graphical-mitre-activity-heat-map"
    view_class = views.GraphicalMitreActivityHeatMapEventListView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
        path("<int:task_id>/report/<str:include_subtechniques>", views.GraphicalMitreActivityHeatMapEventListView.as_view(), name="activity-heat-map-with-options"),
    ]


class GraphicalMitreDetectionPreventionHeatMap(EventReportingPluginPoint):
    category = "Images"
    icon_class = "fas fa-shield-halved"
    title = "Detection and Prevention MITRE Heatmap"
    name = "graphical-mitre-detection-prevention-heat-map"
    view_class = views.GraphicalMitreDetectionPreventionHeatMapEventListView

    urls = [
        path("<int:task_id>/report", view_class.as_view(), name=f"{name}-entry-point"),
        path("<int:task_id>/report/<str:include_subtechniques>", views.GraphicalMitreDetectionPreventionHeatMapEventListView.as_view(), name="detection-prevention-heat-map-with-options"),
    ]
