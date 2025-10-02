from django.urls.converters import IntConverter

class NegativeIntConverter(IntConverter):
    regex = r'-?\d+'  # Matches optional '-' followed by digits
