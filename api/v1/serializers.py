from collections import OrderedDict

from django.contrib.auth.models import User
from django.db import transaction
from rest_framework import serializers

from event_tracker.models import Context, Event, Task, AttackTactic, AttackTechnique, AttackSubTechnique


class NonNullModelSerializer(serializers.ModelSerializer):
    """
    Serializer which omits missing values (empty lists, null values, etc.)
    """
    def to_representation(self, instance):
        result = super(NonNullModelSerializer, self).to_representation(instance)
        return OrderedDict([(key, result[key]) for key in result if result[key] ])


class EventStreamContextSerializer(NonNullModelSerializer):
    """
    Read-only serializer for the source/target in EventStream.
    """
    h = serializers.CharField(source="host")
    u = serializers.CharField(source="user")
    p = serializers.CharField(source="process")

    class Meta:
        model = Context
        fields = ['h', 'u', 'p']


class ContextSerializer(NonNullModelSerializer):
    """
    Serializer for the source/target in Events.
    """

    host = serializers.CharField(default="", allow_blank=True)
    user = serializers.CharField(default="", allow_blank=True)
    process = serializers.CharField(default="", allow_blank=True)

    def validate(self, data):
        """
        Check that at least one of the fields is not empty.
        """
        if not data['host'] and not data['user'] and not data['process']:
            raise serializers.ValidationError("A context must have at least one of host, user or process")
        return data

    class Meta:
        model = Context
        exclude = ['id']
        validators = []  # Remove the models own unique together validator


class EventStreamMitreSerializer(NonNullModelSerializer):
    """
    Read-only serializer for the MITRE ATT&CK references in EventStream.
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
    Top level read-only serializer for EventStream.
    """
    ts = serializers.DateTimeField(source="timestamp")
    te = serializers.DateTimeField(source="timestamp_end", read_only=False)
    op = serializers.CharField(source="operator.username")
    s = EventStreamContextSerializer(source="source")
    t = EventStreamContextSerializer(source="target")
    d = serializers.CharField(source="description")
    e = serializers.CharField(source="raw_evidence")
    o = serializers.CharField(source="outcome")
    ma = EventStreamMitreSerializer(source="*")

    class Meta:
        model = Event
        fields = ['ts', 'te', 'op', 's', 't', 'd', 'e', 'o', 'ma']

class CurrentUserDefault:
    """
    May be applied as a `default=...` value on a serializer field.
    Returns the current user.
    """
    requires_context = True

    def __call__(self, serializer_field):
        return serializer_field.context['request'].user


def get_or_create_source_and_target(validated_data):
    """
    Update a validated data dictionary, possibly including a source or a target, to point at database instances
    """
    # Source Context
    if 'source' in validated_data:
        source_data = validated_data.pop('source')
        source_serializer = ContextSerializer(data=source_data)
        if source_serializer.is_valid(raise_exception=True):
            validated_data['source'], _ = Context.objects.get_or_create(**source_serializer.validated_data)

    # Target context
    if 'target' in validated_data:
        target_data = validated_data.pop('target')
        target_serializer = ContextSerializer(data=target_data)
        if target_serializer.is_valid(raise_exception=True):
            validated_data['target'], _ = Context.objects.get_or_create(**target_serializer.validated_data)


class EventSerializer(NonNullModelSerializer):
    source = ContextSerializer()
    target = ContextSerializer()

    mitre_attack_tactic = serializers.SlugRelatedField(slug_field='mitre_id', queryset=AttackTactic.objects.all(), required=False, allow_null=True)
    mitre_attack_technique = serializers.SlugRelatedField(slug_field='mitre_id', queryset=AttackTechnique.objects.all(), required=False, allow_null=True)
    mitre_attack_subtechnique = serializers.SlugRelatedField(slug_field='mitre_id', queryset=AttackSubTechnique.objects.all(), required=False, allow_null=True)

    operator = serializers.SlugRelatedField(slug_field='username', queryset=User.objects.all(), default=CurrentUserDefault())

    class Meta:
        model = Event
        exclude = ['task', 'starred']

    def validate(self, data):
        """
        Django REST Framework equivalent of :py:func:`event_tracker.models.Event.clean`.
        """
        if 'mitre_attack_tactic' in data and data['mitre_attack_tactic']:
            if 'mitre_attack_technique' in data and data['mitre_attack_technique']:
                if not data['mitre_attack_technique'].tactics.contains(data['mitre_attack_tactic']):
                    raise serializers.ValidationError("MITRE ATT&CK Technique is not associated with Tactic")
        else:
            if 'mitre_attack_technique' in data and data['mitre_attack_technique']:
                raise serializers.ValidationError("Can't define a MITRE ATT&CK Technique without a Tactic")

        if 'mitre_attack_subtechnique' in data and data['mitre_attack_subtechnique']:
            if 'mitre_attack_technique' not in data or not data['mitre_attack_technique']:
                raise serializers.ValidationError("Can't define a MITRE ATT&CK Subtechnique without a Technique")
            if data['mitre_attack_subtechnique'].parent_technique != data['mitre_attack_technique']:
                raise serializers.ValidationError("MITRE ATT&CK Subtechnique is not associated with Technique")

        return data

    def create(self, validated_data):
        # Use a transaction to ensure this is an all or nothing write
        with transaction.atomic():
            get_or_create_source_and_target(validated_data)

            # Hide tasks from the API and just use the first one we have
            validated_data['task_id'] = Task.objects.first().pk

            return Event.objects.create(**validated_data)

    def update(self, instance, validated_data):
        # Use a transaction to ensure this is an all or nothing write
        with transaction.atomic():
            get_or_create_source_and_target(validated_data)

            return Event.objects.update_or_create(pk=instance.pk, defaults=validated_data)[0]
