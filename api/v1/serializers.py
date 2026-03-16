from collections import OrderedDict

from rest_framework import serializers

from event_tracker.models import Context, Event


class NonNullModelSerializer(serializers.ModelSerializer):
    """
    Serializer which omits missing values (empty lists, null values, etc.)
    """
    def to_representation(self, instance):
        result = super(NonNullModelSerializer, self).to_representation(instance)
        return OrderedDict([(key, result[key]) for key in result if result[key] ])


class ContextSerializer(NonNullModelSerializer):
    """
    Serializer for the source/target in EventStream.
    """
    h = serializers.CharField(source="host")
    u = serializers.CharField(source="user")
    p = serializers.CharField(source="process")

    class Meta:
        model = Context
        fields = ['h', 'u', 'p']


class MitreSerializer(NonNullModelSerializer):
    """
    Serializer for the MITRE ATT&CK references in EventStream.
    """
    ta = serializers.CharField(source="mitre_attack_tactic.mitre_id", required=False)
    t = serializers.SerializerMethodField('get_technique_str')
    class Meta:
        model = Event
        fields = ['ta', 't']

    def get_technique_str(self, event):
        if not event.mitre_attack_technique:
            return ''
        else:
            if event.mitre_attack_subtechnique:
                return event.mitre_attack_subtechnique.mitre_id
            else:
                return event.mitre_attack_technique.mitre_id


class EventStreamSerializer(NonNullModelSerializer):
    """
    Top level serializer for EventStream.
    """
    ts = serializers.DateTimeField(source="timestamp")
    te = serializers.DateTimeField(source="timestamp_end", read_only=False)
    op = serializers.CharField(source="operator.username")
    s = ContextSerializer(source="source")
    t = ContextSerializer(source="target")
    d = serializers.CharField(source="description")
    e = serializers.CharField(source="raw_evidence")
    o = serializers.CharField(source="outcome")
    ma = MitreSerializer(source="*")

    class Meta:
        model = Event
        fields = ['ts', 'te', 'op', 's', 't', 'd', 'e', 'o', 'ma']
