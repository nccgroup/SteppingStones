import hashlib
import json
from urllib.parse import urlsplit
import zoneinfo
from enum import IntEnum
from html import escape

import reversion
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from taggit.managers import TaggableManager
from django.db.models import BooleanField
from django.urls import reverse
from django.core import validators
from django.forms.fields import URLField as FormURLField
from django.utils.translation import gettext_lazy as _

timezones = [value for value in sorted(zoneinfo.available_timezones()) if value != 'localtime']


class UserPreferences(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    timezone = models.CharField(max_length=100, choices=zip(timezones, timezones))

    def __str__(self):
        return f"User preferences for {self.user.username}"


class Task(models.Model):
    code = models.CharField(max_length=100, help_text="The shorthand code used to refer to the task internally")
    name = models.CharField(max_length=100, help_text="The name of the task")
    start_date = models.DateTimeField(help_text="The first day of authorised activity on the task")
    end_date = models.DateTimeField(help_text="The last day of authorised activity on the task")

    def __str__(self):
        return f"{self.code} {self.name}"


@reversion.register()
class Context(models.Model):
    process = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    host = models.CharField(max_length=100)

    def get_visible_html(self):
        html = ""
        if self.host:
            html += f"<span class='ctx{self.id if self.id else ''}'><i class='fas fa-network-wired'></i>&nbsp;{escape(self.host)}&emsp;</span>"

        if self.user:
            html += f"<span class='ctx{self.id if self.id else ''}'><i class='fas fa-user'></i>&nbsp;{escape(self.user)}&emsp;</span>"

        if self.process:
            html += f"<span class='ctx{self.id if self.id else ''}'><i class='far fa-window-maximize'></i>&nbsp;{escape(self.process)}</span>"

        return html

    def __str__(self):
        return self.get_visible_html() +\
            f'<span class="rawdata" hidden>{json.dumps([escape(self.host),escape(self.user),escape(self.process)])}</span>'

    def short_string(self):
        short_string = self.user
        short_string += ' on ' if (self.user and self.host) else ''
        short_string += self.host
        short_string += ' (' + self.process + ')' if self.process else ''
        return short_string

    @property
    def colour(self):
        colour = hashlib.shake_128()
        colour.update(self.process.encode("utf-8"))
        colour.update(self.user.encode("utf-8"))
        colour.update(self.host.encode("utf-8"))
        return f"#{colour.hexdigest(3)}"

    class Meta:
        ordering = ['-pk']
        constraints = [
            models.UniqueConstraint(fields=['process', 'user', 'host'], name='unique context')
        ]


@reversion.register()
class Event(models.Model):
    BOOL_CHOICES = ((True, 'Yes'), (False, 'No'))
    TRISTATE_CHOICES = ((True, 'Yes'), (False, 'No'), (None, 'Unknown'))

    class DetectedChoices(models.TextChoices):
        DETECTION_NA = 'N/A', _("Not Applicable"),
        UNKNOWN = 'UNK', _("Unknown"),
        NOT_DETECTED = 'NEG', _("No Trace"),
        PARTIALLY_DETECTED = 'PAR', _("Event Recorded"),
        FULLY_DETECTED = 'FUL', _("Alert Raised"),


    class PreventedChoices(models.TextChoices):
        PREVENTION_NA = 'N/A', _("Not Applicable"),
        NOT_PREVENTED = 'NEG', _("Not Prevented"),
        PARTIALLY_PREVENTED = 'PAR', _("Manual Intervention"),
        FULLY_PREVENTED = 'FUL', _("Blocked as Standard"),


    task = models.ForeignKey(Task, on_delete=models.PROTECT)
    timestamp = models.DateTimeField()
    timestamp_end = models.DateTimeField(null=True, blank=True)
    operator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    mitre_attack_tactic = models.ForeignKey('AttackTactic', on_delete=models.DO_NOTHING, blank=True, null=True)
    mitre_attack_technique = models.ForeignKey('AttackTechnique', on_delete=models.DO_NOTHING, blank=True, null=True)
    mitre_attack_subtechnique = models.ForeignKey('AttackSubTechnique', on_delete=models.DO_NOTHING, blank=True, null=True)
    source = models.ForeignKey(Context, related_name="source", on_delete=models.DO_NOTHING)
    target = models.ForeignKey(Context, related_name="target", on_delete=models.DO_NOTHING)
    description = models.CharField(max_length=1000)
    raw_evidence = models.TextField(blank=True, null=True)
    detected = models.CharField(max_length=3, choices=DetectedChoices.choices, default=DetectedChoices.UNKNOWN)
    prevented = models.CharField(max_length=3, choices=PreventedChoices.choices, default=PreventedChoices.NOT_PREVENTED)
    outcome = models.CharField(max_length=1000, blank=True, null=True)
    starred = BooleanField(default=False)
    tags = TaggableManager()

    class Meta:
        ordering = ['-timestamp']
        permissions = (
            ('change_event_limited', "Can modify a limited set of fields in an event - outcome and detection"),
        )

    def get_absolute_url(self):
        return reverse('event_tracker:event-update', kwargs={'pk': self.id, "task_id": self.task.id})

    def __str__(self):
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M')} {self.description}"


class ImportedEvent(models.Model):
    timestamp = models.DateTimeField()
    timestamp_end = models.DateTimeField(null=True, blank=True)
    operator = models.CharField(max_length=256)
    source_process = models.CharField(max_length=100)
    source_user = models.CharField(max_length=100)
    source_host = models.CharField(max_length=100)
    target_process = models.CharField(max_length=100)
    target_user = models.CharField(max_length=100)
    target_host = models.CharField(max_length=100)
    description = models.CharField(max_length=1000)
    raw_evidence = models.TextField(blank=True, null=True)
    outcome = models.CharField(max_length=1000, blank=True, null=True)
    mitre_tactic = models.CharField(null=True, max_length=6)
    mitre_technique = models.CharField(null=True, max_length=9)
    additional_data = models.TextField(null=True, blank=True)

    event_mappings = GenericRelation("event_tracker.EventMapping", related_query_name='importedevent')


@reversion.register()
class File(models.Model):
    # As this model appears in a formset, making everything optional saves a lot of grief
    filename = models.CharField(max_length=256)
    description = models.CharField(max_length=1000, blank=True, null=True)
    size = models.IntegerField(blank=True, null=True,)  # Size in bytes
    md5_hash = models.CharField(max_length=32, blank=True, null=True, verbose_name="MD5 Hash")  # Hex representation
    sha1_hash = models.CharField(max_length=40, blank=True, null=True, verbose_name="SHA1 Hash")  # Hex representation
    sha256_hash = models.CharField(max_length=64, blank=True, null=True, verbose_name="SHA256 Hash")  # Hex representation

    class Meta:
        constraints = [
            ###
            # Conceptually we have the following constraint, however we need file forms to pass validation when being created
            # so they can be merged into existing objects, and therefore we can't enforce it in Python
            # (hence the overridden validate_constraints() which prevents any constraints that apply to md5_hash ever being
            # applied in Python, however this code ensures the DB has a constraint still
            ###
            models.UniqueConstraint(fields=['filename', 'size', 'md5_hash'], name='unique file')
        ]

    def validate_constraints(self, exclude=None):
        if exclude is None:
            exclude = set()
        exclude.add('md5_hash')
        return super(File, self).validate_constraints(exclude)

    def __str__(self):
        return f"{self.filename}" \
               f"{' (' + str(self.size) + ' bytes)' if self.size is not None else ''}" \
               f"{' - ' + self.description if self.description is not None else ''}" \
               f'<span class="rawdata" hidden>{json.dumps([self.filename, self.size, self.description, self.md5_hash, self.sha1_hash, self.sha256_hash])}</span>'


@reversion.register()
class FileDistribution(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    location = models.CharField(max_length=1000, blank=True, null=True)
    removed = models.BooleanField(default=False, verbose_name="Removed from Target")


class ShortNameManager(models.Manager):
    def get_by_natural_key(self, *shortname):
        """
        This horrible code is required to work around Django's assumption that natural keys are always an array of
        multiple other keys. Our solution is to write out M2M references as a singleton array, then use the
        * operator on the parameter to accept any number of parameters, then joint them back into a single string
        as django will pass in stings as an array of single chars.

        :param shortname: Either the natural key as a string, or the natural key broken into an array of chars.
        :return: The model object with that shortname, regardless of how it was passed in.
        """

        return self.get(shortname="".join(shortname))


class AttackTactic(models.Model):
    mitre_id = models.CharField(max_length=6, unique=True)  # TA0001
    name = models.CharField(max_length=50)  # Initial Access
    shortname = models.CharField(max_length=12, unique=True)  # initial-access
    step = models.IntegerField()  # 1 i.e. the first step in the kill chain

    objects = ShortNameManager()

    class Meta:
        ordering = ['step']

    def natural_key(self):
        return self.shortname

    def __str__(self):
        return f"{self.mitre_id} {self.name}"

    def url(self):
        return f"https://attack.mitre.org/tactics/{ self.mitre_id }/"


class MitreIdManager(models.Manager):
    def get_by_natural_key(self, *mitre_id):
        return self.get(mitre_id="".join(mitre_id))  # Same hack as ShortNameManager, see its class docs


class AttackTechnique(models.Model):
    mitre_id = models.CharField(max_length=5, unique=True)  # T1537
    name = models.CharField(max_length=50)  # Transfer Data to Cloud Account
    tactics = models.ManyToManyField(AttackTactic)
    detection_advice = models.TextField(null=True)  # MITRE provided detection advice in Markdown format

    objects = MitreIdManager()

    class Meta:
        ordering = ['name']

    def natural_key(self):
        return self.mitre_id

    def __str__(self):
        return f"{self.mitre_id} {self.name}"

    def url(self):
        return f"https://attack.mitre.org/techniques/{ self.mitre_id }/"


class AttackSubTechnique(models.Model):
    mitre_id = models.CharField(max_length=9, unique=True)  # T1498.001
    name = models.CharField(max_length=50)  # Transfer Data to Cloud Account
    parent_technique = models.ForeignKey(
        'AttackTechnique',
        on_delete=models.CASCADE)
    detection_advice = models.TextField(null=True)  # MITRE provided detection advice in Markdown format

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.mitre_id} {self.name}"

    def url(self):
        id_parts = self.mitre_id.split('.')
        return f"https://attack.mitre.org/techniques/{ id_parts[0] }/{ id_parts[1]}/"


class HashCatMode(IntEnum):
    Unlisted = -1
    LDAP_SSHA1 = 111
    NTLM = 1000
    Domain_Cached_Credentials_2 = 2100
    LM = 3000
    NetNTLMv1 = 5500
    NetNTLMv2 = 5600
    Kerberos_5_TGSREP_RC4 = 13100  # etype 23
    Kerberos_5_TGSREP_AES128 = 19600  # etype 17
    Kerberos_5_TGSREP_AES256 = 19700  # etype 18
    Kerberos_5_ASREP_RC4 = 18200  # etype 23


class Credential(models.Model):
    source = models.CharField(max_length=200, null=True, blank=True, help_text="The tool or technique which yeilded the hash or secret")
    source_time = models.DateTimeField(null=True, blank=True, default=timezone.now, help_text="Timestamp for when the hash or secret was obtained from the source or imported into Stepping Stones")
    system = models.CharField(max_length=200, null=True, blank=True, db_collation="nocase", help_text="The scope of the account, i.e. the name of the domain or host it applies to")
    account = models.CharField(max_length=200, db_collation="nocase", help_text="The username, without any system prefix or suffix")
    secret = models.CharField(max_length=200, null=True, blank=True, help_text="The password, or API key etc")
    hash = models.CharField(max_length=5500, null=True, blank=True, db_collation="nocase", help_text="A hashed version of the secret, in a form usable by hashcat")  # AES Krb Tickets are ~5500 chars
    hash_type = models.IntegerField(help_text="The hashcat module number for the hash", null=True, blank=True, choices=[(tag.value, f"{tag.name} ({tag.value})") for tag in HashCatMode] )
    purpose = models.CharField(max_length=100, null=True, blank=True, help_text="What the credential is used for")  # Needs to be long enough to include SPNs
    complexity = models.CharField(max_length=30, null=True, blank=True)
    char_mask = models.CharField(max_length=400, null=True, blank=True)  # E.g. ?l?l?d
    char_mask_effort = models.PositiveBigIntegerField(null=True, default=None)  # E.g. (26 * 26 * 10) // 1_000_000
    structure = models.CharField(max_length=100, null=True, blank=True)  # E.g. stringdigit
    enabled = models.BooleanField(default=True)
    haveibeenpwned_count = models.PositiveIntegerField(null=True, default=None) # The number of times this hash appears in the haveibeenpwned dataset if relevant, else null
    cracking_parameters = models.CharField(max_length=500, null=True, blank=True, help_text="The parameters used to crack the hash")

    def __str__(self):
        return f"{self.account}{f'@{self.system}' if self.system else ''}"

    def hash_type_obj(self):
        return HashCatMode(self.hash_type)

    class Meta:
        indexes = [
            models.Index(fields=["hash"]),
            models.Index(fields=["account", "hash"]),
            models.Index(fields=["system", "account"]),
            models.Index(fields=["secret", "hash"]),
        ]
        unique_together = ['system', 'account', 'hash', 'hash_type']


class EventMapping(models.Model):
    object_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    source_object = GenericForeignKey()

    event = models.ForeignKey(
        'Event',
        on_delete=models.CASCADE,
    )


class Webhook(models.Model):
    url = models.URLField(max_length=500)


class BeaconReconnectionWatcher(models.Model):
    beacon = models.ForeignKey(
        'cobalt_strike_monitor.Beacon',
        on_delete=models.CASCADE,
    )


class Neo4jURLFormField(FormURLField):
    # bolt - plaintext, bolt+s - SSL bolt, bolt+ssc - SSL bolt w/ self-signed cert
    default_validators = [validators.URLValidator(schemes=['bolt', 'bolt+s', 'bolt+ssc'])]


class Neo4jURLField(models.URLField):
    # URL field that accepts URLs that start with neo4j schemes, e.g. bolt:// only.
    default_validators = [validators.URLValidator(schemes=['bolt', 'bolt+s', 'bolt+ssc'])]

    def formfield(self, **kwargs):
        return super(Neo4jURLField, self).formfield(**{
            'form_class': Neo4jURLFormField,
        })


class BloodhoundServer(models.Model):
    neo4j_connection_url = Neo4jURLField()
    neo4j_browser_url = models.URLField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    active = models.BooleanField(default=True)

    @property
    def neo4j_connection_url_for_browser(self):
        connection_url = urlsplit(self.neo4j_connection_url)

        scheme = connection_url.scheme.rstrip("+s")

        return f"{scheme}://{self.username}@{connection_url.netloc}"