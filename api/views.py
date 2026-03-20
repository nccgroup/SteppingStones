from rest_framework import generics
from rest_framework.response import Response
from rest_framework.reverse import reverse


class ApiRoot(generics.GenericAPIView):
    """
    Index of all browsable API pages.
    """
    name = 'Stepping Stones API'
    def get(self, request, *args, **kwargs):
        return Response({
            'token_obtain_pair': reverse("token_obtain_pair", request=request),
            'token_refresh': reverse("token_refresh", request=request),
            'events': reverse("event-list", request=request),
            'eventstream': reverse("eventstream-list", request=request),
            })