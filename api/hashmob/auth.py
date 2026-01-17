from durin.auth import TokenAuthentication
from durin.settings import durin_settings


class HashmobAuthentication(TokenAuthentication):
    def authenticate(self, request):
        # Map the api-key header used by Hashmob into the header name & format expected by Django REST Framework
        request.META['HTTP_AUTHORIZATION'] = f"{durin_settings.AUTH_HEADER_PREFIX} {request.META.get('HTTP_API_KEY', '')}"

        return super(HashmobAuthentication, self).authenticate(request)
