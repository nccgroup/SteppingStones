from rest_framework import serializers

class HashMobSubmitSerializer(serializers.Serializer):
    algorithm = serializers.IntegerField()
    founds = serializers.ListField(child=serializers.CharField())
