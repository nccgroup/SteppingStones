from durin.permissions import AllowSpecificClients
from rest_framework.permissions import BasePermission


class ChangeCredentialPermission(BasePermission):
    def has_permission(self, request, view):
        return request.user.has_perm('event_tracker.change_credential')

class HashmobClientPermission(AllowSpecificClients):
    allowed_clients_name = ("hashmob_api",)
