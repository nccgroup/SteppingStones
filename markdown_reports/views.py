from ipaddress import IPv4Address, AddressValueError

import tldextract
from django.db.models import Min
from cobalt_strike_monitor.models import Beacon
from event_tracker.models import File, FileDistribution, Event
from event_tracker.views import EventListView, MitreEventListView


class MarkdownIOCView(EventListView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_filedistribution', 'event_tracker.view_event')
    template_name = 'iocs.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        internal_ips = []
        external_ips = []
        internal_domains = []
        external_domains = []

        for source in self.get_queryset().order_by().values("source__host").distinct():
            host = source['source__host']
            try:
                ipaddress = IPv4Address(host)
                if ipaddress.is_private:
                    # Internal IPs are likely to be within the target network
                    internal_ips.append(ipaddress)
                else:
                    external_ips.append(ipaddress)
            except AddressValueError:
                # Isn't an IP addresses
                domain_parts = tldextract.extract(host)
                if domain_parts.suffix:
                    external_domains.append(host)
                elif host:  # Ensure it's not just the empty string
                    internal_domains.append(host)
        internal_ips.sort()
        external_ips.sort()
        internal_domains.sort()
        external_domains.sort()

        context['internal_sources'] = internal_ips + internal_domains
        context['external_sources'] = external_ips + external_domains

        # Note: Beacons aren't tied to events/tasks so this will be a complete list
        context['visible_beacons'] = Beacon.visible_beacons().order_by("opened")

        context['associated_files'] = (File.objects
            .filter(filedistribution__in=FileDistribution.objects.filter(event__in=self.get_queryset()))
            .annotate(first_use=Min('filedistribution__event__timestamp')).order_by('first_use', 'pk'))

        return context


class MarkdownEventLogsView(EventListView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')
    template_name = 'markdown_event_logs.html'


class MarkdownDetectionAdvice(MitreEventListView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')
    template_name = 'detection_advice.html'
