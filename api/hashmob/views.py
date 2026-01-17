from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from api.hashmob.auth import HashmobAuthentication
from api.hashmob.permissions import ChangeCredentialPermission, HashmobClientPermission
from api.hashmob.serializers import HashMobSubmitSerializer
from event_tracker.views_credentials import UploadCrackedHashes


class HashMobViewSet(ViewSet):
    """
    API endpoint that mimic's elements of https://hashmob.net/api/v2/documentation.
    Matches API auth via "api-key" header.
    """

    authentication_classes = (HashmobAuthentication,)
    permission_classes = (IsAuthenticated, ChangeCredentialPermission, HashmobClientPermission)

    @action(methods=['post'], detail=False)
    def submit(self, request):
        serializer = HashMobSubmitSerializer(request.data)
        print(f"Importing {len(serializer.data["founds"])} new hashes via hashmob emulated API from {request.user.username}")
        upload_handler = UploadCrackedHashes()
        new_accounts, new_hashes = upload_handler.add_credentials("\n".join(serializer.data["founds"]))
        print(f"{request.user.username} cracked {new_hashes} hash(es), affecting {new_accounts} account(s)")

        return Response(status=status.HTTP_200_OK)
