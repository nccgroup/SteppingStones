from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer

from api.v1.permissions import ListEventsPermission
from api.v1.renderers import JSONLRenderer
from api.v1.serializers import EventStreamSerializer
from event_tracker.models import Event


class EventStreamViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API for obtaining events in EventStream format (specify Accept: application/jsonl to match the JSON lines format).
    """
    permission_classes = (IsAuthenticated, ListEventsPermission)
    renderer_classes = [JSONLRenderer, JSONRenderer, BrowsableAPIRenderer]
    serializer_class = EventStreamSerializer
    queryset = Event.objects.all()
