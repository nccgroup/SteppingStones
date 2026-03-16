from rest_framework.permissions import BasePermission


class ListEventsPermission(BasePermission):
    def has_permission(self, request, view):
        return request.user.has_perm('event_tracker.view_event')