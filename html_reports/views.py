from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import Count, Q, Value, F
from django.views.generic import TemplateView

from event_tracker.models import AttackTactic
from event_tracker.views import EventListView


class HTMLEventLogsView(EventListView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')
    template_name = 'html_event_logs.html'


class HTMLMitreDetectionSummaryView(PermissionRequiredMixin, TemplateView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')
    template_name = 'detection_summary.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        total = Count("event")
        detected = Count("event", filter=Q(event__detected='FUL') | Q(event__detected='PAR'))
        prevented = Count("event", filter=Q(event__prevented='FUL') | Q(event__prevented='PAR'))

        results = AttackTactic.objects.annotate(total=total).annotate(detected=detected).annotate(prevented=prevented)\
            .annotate(percent_detected=Value(1.0) * F('detected') / F('total'))\
            .annotate(percent_prevented=Value(1.0) * F('prevented') / F('total')).order_by("step")

        context["tactics"] = results

        return context
