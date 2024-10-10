import csv
import json
import os
import string
from abc import ABC, abstractmethod
from io import BytesIO
from json import JSONDecodeError
from typing import Optional

import json2table
import jsonschema
import reversion
from zipfile import ZipFile, ZIP_DEFLATED

from ansi2html import Ansi2HTMLConverter
from dal_select2_taggit.widgets import TaggitSelect2
from django import forms
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.mixins import UserPassesTestMixin, PermissionRequiredMixin
from django.contrib.auth.models import User
from django.contrib.staticfiles import finders
from django.db import transaction, connection
from django.db.models import Max, Window, F, Q, Value, DateTimeField
from django.db.models.functions import Greatest, Coalesce, Lag
from django.forms import inlineformset_factory
from django.http import JsonResponse, HttpResponse, HttpRequest
from django.shortcuts import render, get_object_or_404, redirect
from django.template.defaultfilters import truncatechars_html
from django.utils import timezone, html
from django.utils.dateparse import parse_datetime
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.views import View
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.generic import ListView, TemplateView
from django_datatables_view.base_datatable_view import BaseDatatableView
from djangoplugins.models import ENABLED
from jsonschema.exceptions import ValidationError
from neo4j.exceptions import ServiceUnavailable
from reversion.views import RevisionMixin
from taggit.forms import TagField
from taggit.models import Tag

from cobalt_strike_monitor.models import TeamServer, Archive, BeaconLog, Beacon, BeaconExclusion, BeaconPresence, \
    Download
from cobalt_strike_monitor.poll_team_server import healthcheck_teamserver
from .models import Task, Event, AttackTactic, AttackTechnique, Context, AttackSubTechnique, FileDistribution, File, \
    EventMapping, Credential, Webhook, BeaconReconnectionWatcher, BloodhoundServer, UserPreferences, \
    ImportedEvent, HashCatMode
from django.urls import reverse_lazy, reverse
from django.views.generic.edit import CreateView, DeleteView, UpdateView, FormView
from datetime import datetime, timedelta

from dal import autocomplete

from .plugins import EventReportingPluginPoint
from .signals import cs_beacon_to_context, cs_beaconlog_to_file, notify_webhook_new_beacon, cs_listener_to_context, \
    get_driver_for
from .templatetags.custom_tags import render_ts_local, breakonpunctuation


@permission_required('event_tracker.view_task')
def index(request):
    tasks = Task.objects.order_by('-start_date')
    context = {'tasks': tasks}
    return render(request, 'index.html', context)


@permission_required('event_tracker.view_attacktechnique')
def techniques_for_tactic(request, tactic):
    tactic = get_object_or_404(AttackTactic, shortname=tactic)
    techniques = AttackTechnique.objects.filter(tactics__exact=tactic)
    result = [{"id":"", "value": "-" * 9}]
    for technique in techniques:
        result.append({"id": technique.id, "value": str(technique)})
    return JsonResponse({"result":result})


@permission_required('event_tracker.view_attacksubtechnique')
def subtechniques_for_technique(request, technique):
    technique = get_object_or_404(AttackTechnique, mitre_id=technique)
    subtechniques = AttackSubTechnique.objects.filter(parent_technique__exact=technique)
    result = [{"id":"", "value": "-" * 9}]
    for subtechnique in subtechniques:
        result.append({"id": subtechnique.id, "value": str(subtechnique)})
    return JsonResponse({"result":result})


@permission_required('event_tracker.admin')
def download_backup(request):
    backup_filename = f"steppingstones-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sqlite3"

    # Defragment the database into a file for export
    with connection.cursor() as cursor:
        cursor.execute(f"vacuum into '{backup_filename}'")

    with open(backup_filename, "rb") as database:
        file_data = database.read()

    os.remove(backup_filename)

    in_memory = BytesIO()
    with ZipFile(in_memory, mode="w", compresslevel=9, compression=ZIP_DEFLATED) as zf:
        # Write database file content to a .zip entry
        zf.writestr(backup_filename, file_data)

    # Go to beginning of the in memory buffer
    in_memory.seek(0)

    return HttpResponse(content=in_memory.read(),
                        headers={'Content-Disposition':
                                f'attachment; filename="steppingstones-{datetime.now().strftime("%Y%m%d-%H%M%S")}.zip"'})


def get_context_queryset():
    return Context.objects\
        .annotate(last_used_source=Max("source__timestamp"), last_used_target=Max("target__timestamp"))\
        .annotate(last_used_of_both=Greatest("last_used_source", "last_used_target"))\
        .annotate(last_used=Coalesce("last_used_of_both","last_used_source","last_used_target"))\
        .order_by("-last_used", "last_used_target")


class ContextAutocomplete(autocomplete.Select2QuerySetView, PermissionRequiredMixin):
    permission_required = 'event_tracker.view_context'

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return Context.objects.none()

        qs = get_context_queryset()
        if self.q:
            qs = qs.filter(process__contains=self.q) | \
                 qs.filter(user__contains=self.q) | \
                 qs.filter(host__contains=self.q)

        return qs


class FileAutocomplete(autocomplete.Select2QuerySetView, PermissionRequiredMixin):
    permission_required = 'event_tracker.view_file'

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return File.objects.none()

        qs = File.objects.all()
        
        if self.q:
            qs = qs.filter(filename__contains=self.q) | \
                 qs.filter(description__contains=self.q)

        return qs


class EventTagAutocomplete(autocomplete.Select2QuerySetView, PermissionRequiredMixin):
    permission_required = 'taggit.view_tag'

    def get_queryset(self):
        if not self.request.user.is_authenticated:
            return Tag.objects.none()

        qs = Tag.objects.all().order_by("name")

        if self.q:
            qs = qs.filter(name__istartswith=self.q)

        return qs


blank_choice = [('', '--- Leave Unchanged ---'),]
class EventBulkEditForm(forms.Form):
    tags = TagField(label="Tag(s) to add", required=False, widget=TaggitSelect2(url='event_tracker:eventtag-autocomplete', attrs={"data-theme": "bootstrap-5"}))
    detected = forms.ChoiceField(label="Set all Detected to", choices=blank_choice + Event.DetectedChoices.choices, initial=None, required=False)
    prevented = forms.ChoiceField(label="Set all Prevented to", choices=blank_choice + Event.PreventedChoices.choices, initial=None, required=False)

class EventBulkEdit(PermissionRequiredMixin, FormView):
    permission_required = 'event_tracker.change_event'
    form_class = EventBulkEditForm
    template_name = "event_tracker/event_bulk_edit.html"
    success_url = "/event-tracker/1"

    def form_valid(self, form):
        for event in Event.objects.filter(starred=True).all():
            event.tags.add(*form.cleaned_data["tags"])
            if form.cleaned_data["detected"]:
                event.detected = form.cleaned_data["detected"]
            if form.cleaned_data["prevented"]:
                event.prevented = form.cleaned_data["prevented"]
            event.save()

        return super().form_valid(form)


class EventListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_event'
    model = Event

    def post(self, request, *args, **kwargs):
        eventfilter = EventFilterForm(request.POST, task_id=kwargs["task_id"])
        if eventfilter.is_valid():
            self.request.session['eventfilter'] = eventfilter.data

        return redirect(request.path)

    def get_queryset(self):
        qs = Event.objects.all()\
            .select_related('mitre_attack_tactic').select_related('mitre_attack_technique').select_related('mitre_attack_subtechnique')\
            .select_related("source").select_related("target")

        eventfilter = EventFilterForm(self.request.session.get('eventfilter'), task_id=self.kwargs["task_id"])

        if eventfilter.is_valid():
            qs = eventfilter.apply_to_queryset(qs)

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['eventfilter'] = EventFilterForm(self.request.session.get('eventfilter'), task_id=self.kwargs["task_id"])

        context['all_starred'] = not self.get_queryset().filter(starred=False).exists()
        context['contexts'] = Context.objects.filter(source__in=self.get_queryset()).distinct() | Context.objects.filter(target__in=self.get_queryset()).distinct()

        if EventReportingPluginPoint.get_plugins_qs().filter(status=ENABLED).exists():
            context['plugins'] = []
            for plugin in EventReportingPluginPoint.get_plugins():
                if plugin.is_access_permitted(self.request.user):
                    context['plugins'].append(plugin)

        return context


class FileListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_file'

    model = FileDistribution
    template_name = 'event_tracker/file_list.html'


class CSVEventListView(EventListView):
    def render_to_response(self, context, **response_kwargs):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="events.csv"'
        writer = csv.writer(response)
        writer.writerow(["Timestamp", "Timestamp End",
                         "Source Host", "Source User", "Source Process",
                         "Target Host", "Target User", "Target Process",
                         "Description", "Raw Evidence", "Outcome", "Detected", "Prevented",
                         "MITRE Tactic ID", "MITRE Tactic Name",
                         "MITRE Technique ID", "MITRE Technique Name",
                         "MITRE Subtechnique ID", "Mitre Subtechnique Name", "Tags"])

        rows = context.get("event_list").values_list("timestamp", "timestamp_end",
                                                     "source__host", "source__user", "source__process",
                                                     "target__host", "target__user", "target__process",
                                                     "description", "raw_evidence", "outcome", "detected", "prevented",
                                                     "mitre_attack_tactic__mitre_id", "mitre_attack_tactic__name",
                                                     "mitre_attack_technique__mitre_id", "mitre_attack_technique__name",
                                                     "mitre_attack_subtechnique__mitre_id", "mitre_attack_subtechnique__name", "id")

        for event in rows:
            writer.writerow(event[:-1] + (list(Event.objects.get(id=event[-1]).tags.all().values_list("name", flat=True)), ))

        return response


class MitreEventListView(EventListView, ABC):
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # -- Event associated tactics, techniques, subtechniques

        events = self.get_queryset()
        event_tactics = AttackTactic.objects.filter(id__in=events.values_list('mitre_attack_tactic__id'))

        event_tactic_dict = dict()
        for tactic in event_tactics:
            event_tactic_dict[tactic] = dict()
            for technique in tactic.attacktechnique_set.filter(id__in=events.filter(mitre_attack_tactic=tactic).values_list('mitre_attack_technique__id')):
                event_tactic_dict[tactic][technique] = technique.attacksubtechnique_set.filter(id__in=events.filter(mitre_attack_tactic=tactic).filter(mitre_attack_technique=technique).values_list('mitre_attack_subtechnique__id'))

        context["event_tactics"] = event_tactic_dict

        # -- All tactics, techniques, subtechniques published by MITRE

        all_tactics = AttackTactic.objects.all()

        all_tactic_dict = dict()
        for tactic in all_tactics:
            all_tactic_dict[tactic] = dict()
            for technique in tactic.attacktechnique_set.all():
                all_tactic_dict[tactic][technique] = technique.attacksubtechnique_set.all()

        context["all_tactics"] = all_tactic_dict

        return context


class FileForm(forms.ModelForm):
    class Meta:
        model = File
        fields = "__all__"

    def save(self, commit=True):
        """
        Override the standard form save() function to merge this form's data over an existing object if it has some
        key attributes the same.
        """
        existing_instance = File.objects.filter(filename=self.cleaned_data["filename"],
                               size=self.cleaned_data["size"],
                               md5_hash=self.cleaned_data["md5_hash"]).exclude(pk=self.instance.id)

        if existing_instance.exists():
            self.instance = existing_instance.get()

            for data, value in self.cleaned_data.items():
                if value:
                    setattr(self.instance, data, value)

            self.instance.save()
    
            return self.instance
        else:
            return super(FileForm, self).save()


class FileDistributionForm(forms.ModelForm):
    class Meta:
        model = FileDistribution
        fields = "__all__"

    file = forms.ModelChoiceField(queryset=File.objects.all(), required=False, empty_label="New File...",
                                    widget=autocomplete.ModelSelect2(url='event_tracker:file-autocomplete', attrs={
                                        "data-placeholder": "New File...", "data-html": True, "data-theme":"bootstrap-5",
                                        "class": "clonable-dropdown"}))

    def __init__(self, *args, **kwargs):
        # Create a nested form for the file data with a prefix based on the formset entry's prefix for uniqueness
        self.fileform = FileForm(auto_id=kwargs['prefix'] + "_%s", prefix=kwargs['prefix'], use_required_attribute=False)
        super(FileDistributionForm, self).__init__(*args, **kwargs)

    def changed_data(self):
        return self.fileform.changed_data() + super(FileDistributionForm, self).changed_data()

    def clean(self):
        cleaned_data = super().clean()

        parsed_file_form = FileForm(data=self.data, auto_id=self.prefix + "_%s", prefix=self.prefix,
                                    instance=self.cleaned_data["file"])

        # We need all FileDistributionForms in the FileDistributionFormSet to be valid for deletions to be honoured by the underlying library

        if not cleaned_data["DELETE"] and not self.empty_permitted:  # Only validate forms that aren't marked for deletion,
                                                                     # and skip any extra forms based on them being "empty_permitted"
            if (not cleaned_data["file"] and not parsed_file_form.is_valid()):
                self.add_error("file", "Must select an existing file or define a new one.")

        return cleaned_data

    def save(self, commit=True):
        if self.empty_permitted \
                and not self.cleaned_data["file"] \
                and not FileForm(data=self.data, auto_id=self.prefix + "_%s", prefix=self.prefix, instance=self.cleaned_data["file"])\
                          .is_valid():
            # This will skip saving any extra forms which haven't been fully completed.
            # It's preferable to halting the whole form from being submitted
            return

        parsed_file_form = FileForm(data=self.data, auto_id=self.prefix + "_%s", prefix=self.prefix,
                                    instance=self.cleaned_data["file"])

        with transaction.atomic():
            has_data_to_store = False

            # validate the form to populate the cleaned_data attribute, so we can look for meaningful data to store
            if parsed_file_form.is_valid():
                for field in parsed_file_form.changed_data:
                    if parsed_file_form.cleaned_data[field] is not None:
                        has_data_to_store = True
                        break

            if has_data_to_store:
                fileobj = parsed_file_form.save()

                # There's a chance the FileForm.save() returned a different, pre-existing File so explicitly (re)set it.
                self.instance.file = fileobj

            super(FileDistributionForm, self).save(commit=commit)


def get_bh_users(tx, q):
    users = set()

    if q:
        result = tx.run('match (n) where (n:User or n:AZUser) and toLower(split(n.name, "@")[0]) CONTAINS toLower($q) return split(n.name, "@")[0] limit 50', q=q)
        for record in result:
            users.add(record[0])

    return users


class UserListAutocomplete(autocomplete.Select2ListView):
    def get_list(self):
        if not self.request.user.has_perm('event_tracker.change_context'):
            return []

        result = set(Context.objects.filter(user__contains=self.q).values_list('user', flat=True).order_by('user').distinct())

        for bloodhound_server in BloodhoundServer.objects.filter(active=True).all():
            driver = get_driver_for(bloodhound_server)

            if driver:
                try:
                    with driver.session() as session:
                        result = result.union(session.execute_read(get_bh_users, self.q))
                except ServiceUnavailable:
                    print("Timeout talking to neo4j for user list autocomplete")

        result = sorted(result, key=lambda s: escape(s.lower()))

        return result


def get_bh_hosts(tx, q):
    hosts = set()

    if q:
        result = tx.run('match (n) where (n:Computer or n:AZDevice) and toLower(split(n.name, ".")[0]) CONTAINS toLower($q) return split(n.name, ".")[0] limit 50', q=q)
        for record in result:
            hosts.add(record[0])

    return hosts


class HostListAutocomplete(autocomplete.Select2ListView):
    def get_list(self):
        if not self.request.user.has_perm('event_tracker.change_context'):
            return []

        result = set(Context.objects.filter(host__contains=self.q).values_list('host', flat=True).order_by('host').distinct())

        for bloodhound_server in BloodhoundServer.objects.filter(active=True).all():
            driver = get_driver_for(bloodhound_server)

            if driver:
                try:
                    with driver.session() as session:
                        result = result.union(session.execute_read(get_bh_hosts, self.q))
                except ServiceUnavailable:
                    print("Timeout talking to neo4j for host list autocomplete")

        result = sorted(result, key=lambda s: escape(s.lower()))

        return result


class ProcessListAutocomplete(autocomplete.Select2ListView):
    def get_list(self):
        if not self.request.user.has_perm('event_tracker.change_context'):
            return []

        result = list(Context.objects.filter(process__contains=self.q).values_list('process', flat=True)
                       .order_by('process').distinct())

        result = sorted(result, key=lambda s: escape(s.lower()))

        return result


class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        exclude = ('starred',)

    task = forms.ModelChoiceField(Task.objects)
    timestamp = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "datetime-local"}))
    timestamp_end = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), required=False)
    operator = forms.ModelChoiceField(User.objects)
    mitre_attack_tactic = forms.ModelChoiceField(AttackTactic.objects, required=False, label="Tactic")
    mitre_attack_technique = forms.ModelChoiceField(AttackTechnique.objects, required=False, label="Technique")
    mitre_attack_subtechnique = forms.ModelChoiceField(AttackSubTechnique.objects, required=False, label="Subtechnique")
    source = forms.ModelChoiceField(get_context_queryset(), required=False, empty_label="New Source...", widget=autocomplete.ModelSelect2(url='event_tracker:context-autocomplete', attrs={"data-placeholder": "New Source...", "data-html": True, "data-theme":"bootstrap-5", "class": "clonable-dropdown"}))
    target = forms.ModelChoiceField(get_context_queryset(), required=False, empty_label="New Target...", widget=autocomplete.ModelSelect2(url='event_tracker:context-autocomplete', attrs={"data-placeholder": "New Target...", "data-html": True, "data-theme":"bootstrap-5", "class": "clonable-dropdown"}))
    description = forms.CharField(widget=forms.Textarea())
    raw_evidence = forms.CharField(label="Raw Evidence", required=False, widget=forms.Textarea(attrs={'class': 'font-monospace', "spellcheck": "false"}))
    source_user = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:user-list-autocomplete', attrs={'class': 'context-field user-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))
    source_host = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:host-list-autocomplete', attrs={'class': 'context-field host-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))
    source_process = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:process-list-autocomplete', attrs={'class': 'context-field process-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))
    target_user = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:user-list-autocomplete', attrs={'class': 'context-field user-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))
    target_host = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:host-list-autocomplete', attrs={'class': 'context-field host-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))
    target_process = forms.CharField(required=False, widget=autocomplete.ListSelect2(url='event_tracker:process-list-autocomplete', attrs={'class': 'context-field process-field', "data-theme": "bootstrap-5", "data-tags": "true", "data-token-separators": "null"}))

    tags = TagField(required=False, widget=TaggitSelect2(url='event_tracker:eventtag-autocomplete', attrs={"data-theme": "bootstrap-5"}))

    def clean(self):
        cleaned_data = super().clean()
        if (not cleaned_data["source"] and
                not cleaned_data["source_user"] and
                not cleaned_data["source_host"] and
                not cleaned_data["source_process"]):
            self.add_error("source", "Must select an existing source or specify a new one.")

        if (not cleaned_data["target"] and
                not cleaned_data["target_user"] and
                not cleaned_data["target_host"] and
                not cleaned_data["target_process"]):
            self.add_error("target", "Must select an existing target or specify a new one.")

        if not cleaned_data["timestamp_end"]:
            cleaned_data["timestamp_end"] = None

        return cleaned_data

    def save(self, commit=True):
        # Create a source
        if not self.cleaned_data["source"]:
            obj, created = Context.objects.get_or_create(host=self.cleaned_data["source_host"],
                                                         user=self.cleaned_data["source_user"],
                                                         process=self.cleaned_data["source_process"],)

            self.instance.source = obj
        # Update a source
        elif self.cleaned_data["source_host"] \
                or self.cleaned_data["source_user"] \
                or self.cleaned_data["source_process"]:
            source_to_mod = self.cleaned_data["source"]
            source_to_mod.host = self.cleaned_data["source_host"]
            source_to_mod.user = self.cleaned_data["source_user"]
            source_to_mod.process = self.cleaned_data["source_process"]
            source_to_mod.save()

        # Create a target
        if not self.cleaned_data["target"]:
            obj, created = Context.objects.get_or_create(user=self.cleaned_data["target_user"],
                                                         host=self.cleaned_data["target_host"],
                                                         process=self.cleaned_data["target_process"],)

            self.instance.target = obj
        # Update a target
        elif self.cleaned_data["target_host"] \
                or self.cleaned_data["target_user"] \
                or self.cleaned_data["target_process"]:
            target_to_mod = self.cleaned_data["target"]
            target_to_mod.host = self.cleaned_data["target_host"]
            target_to_mod.user = self.cleaned_data["target_user"]
            target_to_mod.process = self.cleaned_data["target_process"]
            target_to_mod.save()

        return super().save(commit=commit)


class LimitedEventForm(EventForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, field in self.fields.items():
            if field_name not in ["outcome", "detected"]:
                field.disabled = True

        del self.fields["tags"]


class EventFilterForm(forms.Form):
    tactic = forms.ModelChoiceField(AttackTactic.objects,
                                    required=False,
                                    empty_label="All Tactics",
                                    widget=forms.Select(attrs={'class': 'form-select form-select-sm submit-on-change'}))
    starred = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'submit-on-change'}))
    tag = forms.ModelChoiceField(Event.tags.get_queryset().order_by("name"), required=False, empty_label="All Tags",
                                 widget=forms.Select(attrs={'class': 'form-select form-select-sm submit-on-change'}))

    class Media:
        js = ["scripts/ss-forms.js"]

    def __init__(self, *args, **kwargs):
        task_id = kwargs.pop("task_id", None)
        super().__init__(*args, **kwargs)

        if task_id:
            self.task = get_object_or_404(Task, id=task_id)

        if self.is_valid():
            qs = self.apply_to_queryset(Event.objects.all())

            # Disable widgets if there is no sane choice
            self.fields['tag'].disabled = not self.fields['tag'].queryset.exists()
            self.fields['starred'].disabled = not qs.filter(starred=True).exists()
            self.fields['tactic'].disabled = not self.fields['tactic'].queryset.exists()


    def get_tag_string(self):
        if 'tag' in self.data and self.data['tag']:
            return self.fields['tag'].choices.queryset.get(pk=self.data['tag']).name
        else:
            return ''

    def apply_to_queryset(self, qs):
        qs = qs.filter(task=self.task)

        tactic = self.cleaned_data['tactic']
        if tactic:
            qs = qs.filter(mitre_attack_tactic=tactic)

        tag = self.cleaned_data['tag']
        if tag:
            qs = qs.filter(tags__name=tag)

        if self.cleaned_data['starred']:
            qs = qs.filter(starred=True)

        return qs


FileDistributionFormSet = inlineformset_factory(Event, FileDistribution, form=FileDistributionForm, exclude=[], extra=1, can_delete=True)


class EventCreateView(PermissionRequiredMixin, RevisionMixin, CreateView):
    permission_required = 'event_tracker.add_event'
    model = Event
    form_class = EventForm

    def get_success_url(self):
        if "task_id" in self.kwargs:
            task_id = self.kwargs["task_id"]
        else:
            task_id = Task.objects.order_by("-id").first().id

        return reverse_lazy('event_tracker:event-list',
                            kwargs={"task_id": task_id})

    def get_initial(self):
        task = get_object_or_404(Task, pk=self.kwargs.get('task_id'))
        return {
            "task": task,
            "timestamp": timezone.localtime().strftime("%Y-%m-%dT%H:%M"),
            "operator": self.request.user,
        }

    def get_context_data(self, **kwargs):
        context = super(EventCreateView, self).get_context_data(**kwargs)
        context['action'] = "Create"

        context['contexts'] = Context.objects.all()

        if self.request.POST:
            context["file_distributions_formset"] = FileDistributionFormSet(self.request.POST)
        else:
            context["file_distributions_formset"] = FileDistributionFormSet()
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        file_distributions_formset = context["file_distributions_formset"]

        with reversion.create_revision(atomic=True):
            self.object = form.save()

            # Call "is_valid()" to populate the cleaned_data, we don't care if the formset is 
            # invalid, as we're only going to save valid forms within the formset
            file_distributions_formset.is_valid()

            file_distributions_formset.instance = self.object
            file_distributions_formset.save()

        return super(EventCreateView, self).form_valid(form)


class EventCloneView(EventCreateView):
    def get_initial(self):
        task = get_object_or_404(Task, pk=self.kwargs.get('task_id'))
        original_event = get_object_or_404(Event, pk=self.kwargs.get('event_id'))

        return {
            "task": task,
            "timestamp": timezone.localtime().strftime("%Y-%m-%dT%H:%M"),
            "operator": original_event.operator,

            "mitre_attack_tactic": original_event.mitre_attack_tactic,
            "mitre_attack_technique": original_event.mitre_attack_technique,
            "mitre_attack_subtechnique": original_event.mitre_attack_subtechnique,

            "source": original_event.source,
            "target": original_event.target,

            "tags": ",".join(original_event.tags.names()),

            "description": original_event.description,
            "raw_evidence": original_event.raw_evidence,

            "detected": original_event.detected,
            "prevented": original_event.prevented,

            "outcome": original_event.outcome
        }

    def get_context_data(self, **kwargs):
        context = super(EventCloneView, self).get_context_data(**kwargs)

        if self.request.POST:
            context["file_distributions_formset"] = FileDistributionFormSet(self.request.POST)
        else:
            original_event = get_object_or_404(Event, pk=self.kwargs.get('event_id'))

            initial = []

            for filedistribution in original_event.filedistribution_set.all():
                initial.append({"location": filedistribution.location,
                                "file": filedistribution.file,
                                "removed": filedistribution.removed})

            context["file_distributions_formset"] = FileDistributionFormSet(instance=self.object, initial=initial)
            context["file_distributions_formset"].extra += len(initial)

        return context


class EventLatMoveCloneView(EventCreateView):
    def get_initial(self):
        task = get_object_or_404(Task, pk=self.kwargs.get('task_id'))
        original_event = get_object_or_404(Event, pk=self.kwargs.get('event_id'))

        return {
            "task": task,
            "timestamp": timezone.localtime().strftime("%Y-%m-%dT%H:%M"),
            "operator": original_event.operator,

            "source": original_event.target,
        }


class EventUpdateView(PermissionRequiredMixin, RevisionMixin, UpdateView):
    permission_required = 'event_tracker.change_event'
    model = Event
    form_class = EventForm

    def get_success_url(self):
        return reverse_lazy('event_tracker:event-list',
                            kwargs={"task_id": self.kwargs["task_id"]})

    def get_initial(self):
        initial = {"timestamp": timezone.localtime(self.object.timestamp).strftime("%Y-%m-%dT%H:%M")}
        if self.object.timestamp_end:
            initial["timestamp_end"] = timezone.localtime(self.object.timestamp_end).strftime("%Y-%m-%dT%H:%M")
        return initial

    def get_context_data(self, **kwargs):
        context = super(EventUpdateView, self).get_context_data(**kwargs)
        context['action'] = "Update"

        context['contexts'] = Context.objects.all()

        if self.request.POST:
            context["file_distributions_formset"] = FileDistributionFormSet(self.request.POST, instance=self.object)
        else:
            context["file_distributions_formset"] = FileDistributionFormSet(instance=self.object)
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        file_distributions_formset = context["file_distributions_formset"]

        with reversion.create_revision(atomic=True):
            self.object = form.save()
            
            # Call "is_valid()" to populate the cleaned_data, we don't care if the formset is 
            # invalid, as we're only going to save valid forms within the formset
            file_distributions_formset.is_valid()

            file_distributions_formset.instance = self.object
            file_distributions_formset.save()

        return super(EventUpdateView, self).form_valid(form)


class LimitedEventUpdateView(EventUpdateView):
    permission_required = 'event_tracker.change_event_limited'
    model = Event
    form_class = LimitedEventForm
    template_name = "event_tracker/event_form_limited.html"


class EventDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'event_tracker.delete_event'
    model = Event

    def get_success_url(self):
        return reverse_lazy('event_tracker:event-list',
                            kwargs={"task_id": self.kwargs["task_id"]})


# --- Team Server Views ---
class TeamServerListView(PermissionRequiredMixin, ListView):
    permission_required = 'cobalt_strike_monitor.view_teamserver'
    model = TeamServer
    ordering = ['description']


class TeamServerConfigView(TeamServerListView):
    template_name = "cobalt_strike_monitor/teamserver_config.html"


class TeamServerCreateView(PermissionRequiredMixin, CreateView):
    permission_required = 'cobalt_strike_monitor.add_teamserver'
    model = TeamServer
    fields = ['description', 'hostname', 'port', 'password', 'active']

    def get_success_url(self):
        return reverse_lazy('event_tracker:team-server-list')

    def get_context_data(self, **kwargs):
        context = super(TeamServerCreateView, self).get_context_data(**kwargs)
        context['action'] = "Create"
        return context


class TeamServerUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = 'cobalt_strike_monitor.change_teamserver'
    model = TeamServer
    fields = ['description', 'hostname', 'port', 'password', 'active']

    def get_success_url(self):
        return reverse_lazy('event_tracker:team-server-list')

    def get_context_data(self, **kwargs):
        context = super(TeamServerUpdateView, self).get_context_data(**kwargs)
        context['action'] = "Update"
        return context


class TeamServerDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'cobalt_strike_monitor.delete_teamserver'
    model = TeamServer

    def get_success_url(self):
        return reverse_lazy('event_tracker:team-server-list')


class TeamServerHealthCheckView(TemplateView):
    template_name = "cobalt_strike_monitor/teamserver_healthcheck.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tcp_error, aggressor_output, ssbot_status, found_jvm = healthcheck_teamserver(kwargs["serverid"])
        context["tcp_error"] = tcp_error
        context["found_jvm"] = found_jvm

        if aggressor_output:
            conv = Ansi2HTMLConverter()
            context["aggressor_output"] = mark_safe(conv.convert(aggressor_output, full=False))

        if ssbot_status:
            conv = Ansi2HTMLConverter()
            context["ssbot_status"] = mark_safe(conv.convert(ssbot_status, full=False))
        return context


# -- CS Logs views
class CSLogsListView(PermissionRequiredMixin, TemplateView):
    permission_required = 'cobalt_strike_monitor.view_archive'
    template_name = "cobalt_strike_monitor/archive_list.html"


class FilterableDatatableView(ABC, BaseDatatableView):
    filter_column_mapping = {}

    def filter_search_builder(self):
        q = None

        criteria = 0
        while f'searchBuilder[criteria][{criteria}][data]' in self.request.GET.dict().keys():
            prefix = f'searchBuilder[criteria][{criteria}]'
            criteria += 1

            column = self.request.GET.get(prefix + "[data]")
            condition = self.request.GET.get(prefix + "[condition]")
            value1 = self.request.GET.get(prefix + "[value1]")
            value2 = self.request.GET.get(prefix + "[value2]", None)

            if not column or not condition or not value1:
                continue

            if column in self.filter_column_mapping:
                query_column = self.filter_column_mapping[column]
                value1 = timezone.make_aware(parse_datetime(value1))
                if value2:
                    value2 = timezone.make_aware(parse_datetime(value2))
            else:
                query_column = "unknown_column"

            multivalue = False
            if condition == "<":
                query_condition = "lte"
            elif condition == ">":
                query_condition = "gte"
            elif condition == "between":
                query_condition = "range"
                multivalue = True
            else:
                query_condition = "unknown_condition"

            kwarg = dict()
            key = f'{query_column}__{query_condition}'

            if multivalue:
                kwarg[key] = [value1, value2]
            else:
                kwarg[key] = value1

            if q is None:
                q = Q(**kwarg)
            else:
                if self.request.GET.get('searchBuilder[logic]') == 'AND':
                    q &= Q(**kwarg)
                elif self.request.GET.get('searchBuilder[logic]') == 'OR':
                    q |= Q(**kwarg)

        return q

    def filter_queryset(self, qs):
        # Handle SearchBuilder params
        search_builder_q = self.filter_search_builder()
        if search_builder_q is not None:
            qs = qs.filter(search_builder_q)

        # Handle free text search params
        search = self.request.GET.get('search[value]', None)
        if search:
            terms = search.split(" ")
            for term in terms:
                qs = self.filter_queryset_by_searchterm(qs, term)

        return qs

    @abstractmethod
    def filter_queryset_by_searchterm(self, qs, terms):
        pass


class CSLogsListJSON(PermissionRequiredMixin, FilterableDatatableView):
    permission_required = 'cobalt_strike_monitor.view_archive'
    model = Archive
    columns = ['when', 'source', 'target', 'data', 'tactic', '']
    order_columns = ['when', '', '', 'data', 'tactic', '']
    filter_column_mapping = {'Timestamp': 'when'}

    def apply_row_filter(self, qs):
        # Removed hidden beacons, prefetches beacon data, remove empty rows
        return qs.filter(beacon__in=Beacon.visible_beacons()) \
                .select_related("beacon").select_related("beacon__listener") \
                .exclude(data="")

    def get_initial_queryset(self):
        # Rows with type task where there is no input at the same time nor 1 second earlier
        task_rows_without_input = (Archive.objects.filter(type="task")
            # Exclude task rows whose timestamp is the same as an existing input row
            .exclude(when__in=Archive.objects.filter(type="input").values("when"))
            # Exclude task rows whose timestamp is one second later than an existing input row
            .exclude(when__in=Archive.objects.filter(type="input").annotate(
                    one_sec_later=timedelta(seconds=1) + F("when")).values("one_sec_later")))

        input_rows = Archive.objects.filter(type="input")

        return self.apply_row_filter(input_rows | task_rows_without_input)

    def render_column(self, row, column):
        # We want to render some columns in a special way
        if column == 'when':
            return render_ts_local(row.when),
        elif column == 'source':
            if hasattr(row.beacon.listener, "althost") and row.beacon.listener.althost:
                return f'<ul class="fa-ul"><li><span class="fa-li text-muted"><i class="fas fa-network-wired"></i></span>{ escape(row.beacon.listener.althost) }</li></ul>'
            elif hasattr(row.beacon.listener, "host") and row.beacon.listener.host:
                return f'<ul class="fa-ul"><li><span class="fa-li text-muted"><i class="fas fa-network-wired"></i></span>{ escape(row.beacon.listener.host) }</li></ul>'
            else:
                return "-"
        elif column == 'target':
            result = '<ul class="fa-ul">'

            if row.beacon.computer:
                result += f'<li><span class="fa-li text-muted"><i class="fas fa-network-wired"></i></span>{ escape(row.beacon.computer) }</li>\n'

            if row.beacon.user:
                result += f'<li><span class="fa-li text-muted"><i class="fas fa-user"></i></span>{ escape(row.beacon.user) }</li>\n'

            if row.beacon.process:
                result += f'<li><span class="fa-li text-muted"><i class="far fa-window-maximize"></i></span>{ escape(row.beacon.process) } (PID: {escape(row.beacon.pid)})</li>\n'

            if '<li>' not in result:
                result += "-"

            result += '</ul>'
            return result
        elif column == 'data':
            result = ""
            if row.associated_archive_tasks_description:
                result += f"<span class='description'>{row.associated_archive_tasks_description}</span>"

            if row.type == "input":
                result += f"<pre><code>{row.data}</code></pre>"

            result += f"<pre class='output'><code>{html.escape("\n".join(row.associated_beaconlog_output.values_list('data', flat=True)))}</code><pre>"

            return result
        elif column == '':  # The column with button in
            if row.event_mappings.exists() and self.request.user.has_perm('event_tracker.change_event'):
                return f'<a href="{reverse("event_tracker:event-update", args=[row.event_mappings.first().event.task_id, row.event_mappings.first().event.id])}" role="button" class="btn btn-primary btn-sm" data-toggle="tooltip" title="Edit Event"><i class="fa-regular fa-pen-to-square"></i></a>'
            elif (not row.event_mappings.exists()) and self.request.user.has_perm('event_tracker.add_event'):
                return f'<a href="{reverse("event_tracker:cs-log-to-event", args=[row.id])}" role="button" class="btn btn-success btn-sm" data-toggle="tooltip" title="Clone to Event"><i class="far fa-copy"></i></a>'
            else:
                return ""
        else:
            return truncatechars_html((super(CSLogsListJSON, self).render_column(row, column)), 400)

    def filter_queryset_by_searchterm(self, qs, term):
        q = Q(beacon__listener__althost__icontains=term) | Q(beacon__listener__host__icontains=term) | \
            Q(beacon__computer__icontains=term) | Q(beacon__user__icontains=term) | Q(
            beacon__process__icontains=term) | \
            Q(data__icontains=term) | Q(tactic__icontains=term) | Q(beacon__pid=term)

        return qs.filter(q)

# -- EventStream List

class EventStreamListView(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.view_eventstream'
    template_name = "event_tracker/eventstream_list.html"


class EventStreamListJSON(PermissionRequiredMixin, FilterableDatatableView):
    permission_required = 'event_tracker.view_eventstream'
    model = ImportedEvent
    columns = ['timestamp', 'source', 'target', 'description', 'mitre_tactic', 'additional_data', '']
    order_columns = ['timestamp', '', '', 'description', 'mitre_tactic', '', '']
    filter_column_mapping = {'Timestamp': 'timestamp'}

    #TODO render & sort on MITRE technique if no tactic is provided

    def get_initial_queryset(self):
        return ImportedEvent.objects

    def render_column(self, row, column):
        # We want to render some columns in a special way
        if column == 'timestamp':
            return render_ts_local(row.timestamp)
        elif column == 'source':
            dummy_context = Context(host=row.source_host, user=row.source_user, process=row.source_process)
            return dummy_context.get_visible_html()
        elif column == 'target':
            dummy_context = Context(host=row.target_host, user=row.target_user, process=row.target_process)
            return dummy_context.get_visible_html()
        elif column == 'description':
            description = row.description
            if row.raw_evidence:
                description += f'<pre class="mt-3 mb-0"><code>{ breakonpunctuation(escape(row.raw_evidence)) }</code></pre>'
            return description
        elif column == 'additional_data' and row.additional_data:
            additional_data_dict = json.loads(row.additional_data)
            escaped_dict = {}
            for key, value in additional_data_dict.items():
                escaped_dict[escape(key)] = escape(value)
            return json2table.convert(escaped_dict, table_attributes={'class': 'table shadow-sm table-sm table-borderless table-striped-columns mb-0'})
        elif column == '':  # The column with button in
            if row.event_mappings.exists() and self.request.user.has_perm('event_tracker.change_event'):
                return f'<a href="{reverse("event_tracker:event-update", args=[row.event_mappings.first().event.task_id, row.event_mappings.first().event.id])}" role="button" class="btn btn-primary btn-sm" data-toggle="tooltip" title="Edit Event"><i class="fa-regular fa-pen-to-square"></i></a>'
            elif (not row.event_mappings.exists()) and self.request.user.has_perm('event_tracker.add_event'):
                return f'<a href="{reverse("event_tracker:eventstream-to-event", args=[row.id])}" role="button" class="btn btn-success btn-sm" data-toggle="tooltip" title="Clone to Event"><i class="far fa-copy"></i></a>'
            else:
                return ""
        else:
            return truncatechars_html((super(EventStreamListJSON, self).render_column(row, column)), 400)

    def filter_queryset_by_searchterm(self, qs, term):
        q = Q(operator__icontains=term) | Q(description__icontains=term) | \
            Q(source_user__icontains=term) | Q(source_host__icontains=term) | Q(source_process__icontains=term) | \
            Q(target_user__icontains=term) | Q(target_host__icontains=term) | Q(target_process__icontains=term) | \
            Q(mitre_tactic__icontains=term) | Q(mitre_technique__icontains=term) | Q(additional_data__icontains=term)

        return qs.filter(q)


class EventStreamUploadForm(forms.Form):
    file = forms.FileField(help_text="A text file containing an EventStream JSON blob per line", widget=forms.FileInput(attrs={'accept':'.json,text/json'}))


class EventStreamUpload(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.add_eventstream'
    template_name = "event_tracker/eventstream_upload.html"

    def __init__(self):
        super().__init__()
        with open(finders.find("eventstream/eventstream.schema.json")) as schemafp:
            self.schema = json.load(schemafp)

    def get_context_data(self, **kwargs):
        context = super(TemplateView, self).get_context_data(**kwargs)
        context['form'] = EventStreamUploadForm()
        return context

    def post(self, request, *args, **kwargs):
        form = EventStreamUploadForm(request.POST, request.FILES)
        if form.is_valid():
            # There's a risk that a hash spans two chunks and therefore won't get captured by regex, so split on
            # newlines
            previous_chunk = ""

            for chunk in request.FILES['file'].chunks():
                chunk_txt = chunk.decode("UTF-8")
                last_newline = chunk_txt.rfind("\n")

                chunk_main = previous_chunk + chunk_txt[:last_newline]
                self.add_single_eventstream(chunk_main)
                previous_chunk = chunk_txt[last_newline:]

            # Handle final part of upload between last newline and EOF
            if previous_chunk:
                self.add_single_eventstream(previous_chunk)

            return redirect(reverse_lazy('event_tracker:eventstream-list'))

    def add_single_eventstream(self, lines_to_parse):
        for line in lines_to_parse.split("\n"):
            line.strip()
            if line:
                try:
                    eventstream_dict = json.loads(line)
                    jsonschema.validate(instance=eventstream_dict, schema=self.schema)
                    imported_event_dict = {  # Optional field defaults:
                        "timestamp_end": None,
                        "operator": "",
                        "source_process": "",
                        "source_user": "",
                        "source_host": "",
                        "target_process": "",
                        "target_user": "",
                        "target_host": "",
                        "mitre_tactic": None,
                        "mitre_technique": None,
                        "outcome": None,
                        "description": "",
                        "raw_evidence": None
                    }
                    imported_event_dict["timestamp"] = parse_datetime(eventstream_dict.pop("ts"))

                    if "d" in eventstream_dict:
                        imported_event_dict["description"] = eventstream_dict.pop("d")

                    if "e" in eventstream_dict:
                        imported_event_dict["raw_evidence"] = eventstream_dict.pop("e")

                    if "te" in eventstream_dict:
                        imported_event_dict["timestamp_end"] = parse_datetime(eventstream_dict.pop("te"))

                    if "op" in eventstream_dict:
                        imported_event_dict["operator"] = (eventstream_dict.pop("op"))

                    if "s" in eventstream_dict:
                        s = eventstream_dict.pop("s")
                        if "h" in s:
                            imported_event_dict["source_host"] = s["h"]
                        if "u" in s:
                            imported_event_dict["source_user"] = s["u"]
                        if "p" in s:
                            imported_event_dict["source_process"] = s["p"]

                    if "t" in eventstream_dict:
                        t = eventstream_dict.pop("t")
                        if "h" in t:
                            imported_event_dict["target_host"] = t["h"]
                        if "u" in t:
                            imported_event_dict["target_user"] = t["u"]
                        if "p" in t:
                            imported_event_dict["target_process"] = t["p"]

                    if "ma" in eventstream_dict:
                        ma = eventstream_dict.pop("ma")
                        if "ta" in ma:
                            imported_event_dict["mitre_tactic"] = ma["ta"]
                        if "t" in ma:
                            imported_event_dict["mitre_technique"] = ma["t"]

                    if "o" in eventstream_dict:
                        imported_event_dict["outcome"] = eventstream_dict.pop("o")

                    if eventstream_dict:  # If there's still data in the JSON
                        imported_event_dict["additional_data"] = json.dumps(eventstream_dict)

                    ImportedEvent.objects.get_or_create(**imported_event_dict)
                except ValidationError as e:
                    print(f"Schema Validation Error: {e}")
                except JSONDecodeError as e:
                    print(f"JSON Error: {e}")

class EventStreamToEventView(EventCreateView):
    def get_initial(self):
        task = Task.objects.order_by("-id").first()
        imported_event = get_object_or_404(ImportedEvent, pk=self.kwargs.get('pk'))

        tactic = None
        technique = None
        subtechnique = None

        if imported_event.mitre_tactic:
            tactic = AttackTactic.objects.get(mitre_id=imported_event.mitre_tactic)

        if imported_event.mitre_technique:
            try:
                if "." in imported_event.mitre_technique:
                    # It will be a subtechnique:
                    subtechnique = AttackSubTechnique.objects.get(mitre_id=imported_event.mitre_technique)
                    if subtechnique:
                        # Reset the string we're parsing into just the technique part
                        imported_event.mitre_technique = imported_event.mitre_technique.split(".")[0]

                # Parse the string as a technique
                technique = AttackTechnique.objects.get(mitre_id=imported_event.mitre_technique)
                if not tactic:
                    # Guess at the first of the applicable tactics
                    tactic = technique.tactics.first()
            except (AttackTechnique.DoesNotExist, AttackSubTechnique.DoesNotExist):
                pass

        if imported_event.operator:
            operator = User.objects.filter(username__iexact=imported_event.operator).first()
        else:
            operator = None

        source = None
        if imported_event.source_host or imported_event.source_user or imported_event.source_process:
            source, _ = Context.objects.get_or_create(host=imported_event.source_host,
                                                   user=imported_event.source_user,
                                                   process=imported_event.source_process)

        target = None
        if imported_event.target_host or imported_event.target_user or imported_event.target_process:
            target, _ = Context.objects.get_or_create(host=imported_event.target_host,
                                                   user=imported_event.target_user,
                                                   process=imported_event.target_process)

        return {
            "task": task,
            "timestamp": imported_event.timestamp,
            "timestamp_end": imported_event.timestamp_end,
            "source": source,
            "target": target,
            "operator": operator,
            "mitre_attack_tactic": tactic,
            "mitre_attack_technique": technique,
            "mitre_attack_subtechnique": subtechnique,
            "description": imported_event.description,
            "raw_evidence": imported_event.raw_evidence,
            "outcome": imported_event.outcome,
        }

    def form_valid(self, form):
        response = super(EventStreamToEventView, self).form_valid(form)

        imported_event = get_object_or_404(ImportedEvent, pk=self.kwargs.get('pk'))

        mapping = EventMapping(source_object=imported_event, event=self.object)
        mapping.save()

        return response

# -- CS Uploads

class CSUploadsListView(PermissionRequiredMixin, ListView):
    permission_required = 'cobalt_strike_monitor.view_archive'
    template_name = "cobalt_strike_monitor/uploads_list.html"

    def get_queryset(self):
        return (Archive.objects.filter(beacon__in=Beacon.visible_beacons())
                .filter(type="indicator", data__startswith="file:").order_by("-when"))


class CSDownloadsListView(PermissionRequiredMixin, ListView):
    permission_required = 'cobalt_strike_monitor.view_download'
    template_name = "cobalt_strike_monitor/downloads_list.html"

    def get_queryset(self):
        return Download.objects.filter(beacon__in=Beacon.visible_beacons()).order_by("-date")


class CSBeaconsListView(PermissionRequiredMixin, ListView):
    permission_required = 'cobalt_strike_monitor.view_beacon'
    template_name = "cobalt_strike_monitor/beacon_list.html"

    def get_queryset(self):
        return Beacon.visible_beacons().order_by("-opened")

    def get_context_data(self, **kwargs):
        context = super(CSBeaconsListView, self).get_context_data()
        context["reconnection_watcher_bids"] = BeaconReconnectionWatcher.objects.values_list("beacon", flat=True)
        return context


@permission_required('cobalt_strike_monitor.add_beaconreconnectionwatcher')
def beaconwatch_add(request, beacon_id):
    BeaconReconnectionWatcher.objects.get_or_create(beacon_id=beacon_id)
    return redirect("event_tracker:cs-beacons-list")


@permission_required('cobalt_strike_monitor.delete_beaconreconnectionwatcher')
def beaconwatch_remove(request, beacon_id):
    try:
        BeaconReconnectionWatcher.objects.get(beacon_id=beacon_id).delete()
    except:
        pass  # The alert may have already fired, so ignore any errors in deleting it
    return redirect("event_tracker:cs-beacons-list")


class CSBeaconsTimelineView(PermissionRequiredMixin, TemplateView):
    permission_required = ('cobalt_strike_monitor.view_beacon','cobalt_strike_monitor.view_beaconpresence')
    template_name = "cobalt_strike_monitor/beacon_timeline.html"

    def get_context_data(self, *, object_list=None, **kwargs):
        data = dict()

        max_sleep = BeaconPresence.objects.filter(beacon__in=Beacon.visible_beacons())\
            .all().aggregate(Max('sleep_seconds'))['sleep_seconds__max']

        for beacon in Beacon.visible_beacons().all():
            if beacon.beaconpresence_set.exists():
                group = f"{beacon.user} {beacon.computer}"
                label = f"{beacon.process} (PID: {beacon.pid})"

                if group not in data:
                    data[group] = dict()

                if label not in data[group]:
                    data[group][label] = []

                for presence in beacon.beaconpresence_set.all():
                    data[group][label].append({"from": presence.first_checkin, "to": presence.last_checkin,
                                               "sleep": presence.sleep_seconds, "jitter": presence.sleep_jitter,
                                               "sleep_scale": 0 if max_sleep == 0 else presence.sleep_seconds / max_sleep})

        return {"timeline":data}


def previous_hop_to_context(beacon):
    """
    Generate a SS Context object for the beacon's previous hop, taking into account the possibility of chained beacons
    """
    if beacon.parent_beacon:
        return cs_beacon_to_context(None, beacon.parent_beacon)
    else:
        return cs_listener_to_context(None, beacon.listener)


class CSLogToEventView(EventCreateView):
    def get_initial(self):
        task = Task.objects.order_by("-id").first()
        cs_archive = get_object_or_404(Archive, pk=self.kwargs.get('pk'))

        tactic = None
        technique = None
        subtechnique = None

        if cs_archive.data.startswith("file: "):
            description = "Uploaded file to target"
        else:
            description = cs_archive.data

        # Find associated MITRE tactic:
        tactic_record = cs_archive.associated_archive_tasks.filter(tactic__isnull=False).exclude(tactic='').first()

        if tactic_record:
            cs_mitre_refs = tactic_record.tactic.split(",")  # These are typically techniques, not tactics, but CS names them wrong
            for cs_mitre_ref in cs_mitre_refs:
                try:
                    if "." in cs_mitre_ref:
                        # It may be a subtechnique:
                        subtechnique = AttackSubTechnique.objects.get_by_natural_key(cs_mitre_ref)
                        if subtechnique:
                            # Reset the string we're parsing into just the technique part
                            cs_mitre_ref = cs_mitre_ref.split(".")[0]

                    # Parse the string as a technique
                    technique = AttackTechnique.objects.get_by_natural_key(cs_mitre_ref)
                    if technique:
                        tactic = technique.tactics.first()
                        break
                except (AttackTechnique.DoesNotExist, AttackSubTechnique.DoesNotExist):
                    pass

        # Operator determined by the last user to provide input to that beacon
        associated_input_command = cs_archive.associated_beaconlog_input

        if associated_input_command:
            # Do a "fuzzy" match to find a user with the same case insensitive username as the operator,
            # ignoring any trailing digits which are sometimes added to CS operator logins to workaround concurrent
            # logins.
            operator = User.objects.filter(username__iexact=associated_input_command.operator.rstrip(string.digits)).first()
        else:
            operator = None

        input_evidence = cs_archive.data
        output_evidence = "\n".join(cs_archive.associated_beaconlog_output.values_list('data', flat=True))

        return {
            "task": task,
            "timestamp": timezone.localtime(cs_archive.when).strftime("%Y-%m-%dT%H:%M"),
            "source": previous_hop_to_context(cs_archive.beacon),
            "target": cs_beacon_to_context(None, cs_archive.beacon),
            "operator": operator,
            "mitre_attack_tactic": tactic,
            "mitre_attack_technique": technique,
            "mitre_attack_subtechnique": subtechnique,
            "description": cs_archive.associated_archive_tasks_description,
            "raw_evidence": f"{input_evidence}{'\n\n' + output_evidence if output_evidence else ''}" if cs_archive.type == "input" else None
        }

    def get_context_data(self, **kwargs):
        context = super(EventCreateView, self).get_context_data(**kwargs)

        cslog = get_object_or_404(Archive, pk=self.kwargs.get('pk'))
        if cslog.data.startswith("file: ") and not self.request.POST:
            file, location = cs_beaconlog_to_file(cslog.data)
            initial = [{"location": location,
                        "file": file,
                        "removed": False
                        }]

            context["file_distributions_formset"] = FileDistributionFormSet(initial=initial)
            context["file_distributions_formset"].extra += len(initial)
        else:
            # This should come from the super call - confused...
            if self.request.POST:
                context["file_distributions_formset"] = FileDistributionFormSet(self.request.POST)
            else:
                context["file_distributions_formset"] = FileDistributionFormSet()

        context['action'] = "Create"

        return context

    def form_valid(self, form):
        response = super(CSLogToEventView, self).form_valid(form)

        archive = get_object_or_404(Archive, pk=self.kwargs.get('pk'))

        mapping = EventMapping(source_object=archive, event=self.object)
        mapping.save()

        return response

class CSDownloadToEventView(EventCreateView):
    def get_initial(self):
        task = Task.objects.order_by("-id").first()
        download = get_object_or_404(Download, pk=self.kwargs.get('pk'))

        # Collection
        tactic = AttackTactic.objects.get(mitre_id="TA0009")

        if download.path.startswith("\\\\"):
            # Data from network shared drive
            technique = AttackTechnique.objects.get(mitre_id="T1039")
        else:
            # Data from local system
            technique = AttackTechnique.objects.get(mitre_id="T1005")

        return {
            "task": task,
            "timestamp": timezone.localtime(download.date).strftime("%Y-%m-%dT%H:%M"),
            "source": cs_beacon_to_context(None, download.beacon),
            "target": previous_hop_to_context(download.beacon),
            "operator": None,
            "mitre_attack_tactic": tactic,
            "mitre_attack_technique": technique,
            "mitre_attack_subtechnique": None,

            "description": f"Downloaded \"{download.name}\" ({download.size:,} bytes) from {download.path}"
        }

    def form_valid(self, form):
        response = super(CSDownloadToEventView, self).form_valid(form)

        download = get_object_or_404(Download, pk=self.kwargs.get('pk'))

        mapping = EventMapping(source_object=download, event=self.object)
        mapping.save()

        return response


class CSBeaconToEventView(EventCreateView):
    def get_initial(self):
        task = Task.objects.order_by("-id").first()
        beacon = get_object_or_404(Beacon, pk=self.kwargs.get('pk'))

        tactic = AttackTactic.objects.get(mitre_id="TA0011")

        # Defaults:
        technique = AttackTechnique.objects.get(mitre_id="T1095")  # Non-application layer protocol
        subtechnique = None
        protocol = ""

        if beacon.listener:
            # Assuming HTTP listener
            if beacon.listener.payload == "windows/beacon_https/reverse_https":
                if beacon.listener.host != beacon.listener.althost:
                    # Assume domain fronting
                    technique = AttackTechnique.objects.get(mitre_id="T1090")
                    subtechnique = AttackSubTechnique.objects.get(mitre_id="T1090.004")
                    protocol = "domain-fronted HTTPS"
                else:
                    # Assume direct connection
                    technique = AttackTechnique.objects.get(mitre_id="T1071")
                    subtechnique = AttackSubTechnique.objects.get(mitre_id="T1071.001")
                    protocol = "direct HTTPS"
            elif beacon.listener.payload == "windows/beacon_bind_pipe":
                technique = AttackTechnique.objects.get(mitre_id="T1090")
                subtechnique = AttackSubTechnique.objects.get(mitre_id="T1090.001")
                protocol = "SMB Named Pipe"

        return {
            "task": task,
            "timestamp": timezone.localtime(beacon.opened).strftime("%Y-%m-%dT%H:%M"),
            "source": cs_beacon_to_context(None, beacon),
            "target": previous_hop_to_context(beacon),
            "operator": None,
            "mitre_attack_tactic": tactic,
            "mitre_attack_technique": technique,
            "mitre_attack_subtechnique": subtechnique,

            "description": f"New {protocol} command and control connection from Cobalt Strike beacon on {beacon.os_human}".replace("  ", " "),
            "outcome": f"Remote {'administrative' if beacon.user.endswith(' *') else ''} control of device".replace("  ", " ")
        }

    def form_valid(self, form):
        response = super(CSBeaconToEventView, self).form_valid(form)

        beacon = get_object_or_404(Beacon, pk=self.kwargs.get('pk'))

        mapping = EventMapping(source_object=beacon, event=self.object)
        mapping.save()

        return response


class BeaconExclusionForm(forms.Form):
    exclusion_type = forms.ChoiceField(choices=[("id", "id"),
                                                ("user", "user"),
                                                ("computer", "computer"),
                                                ("process", "process"),
                                                ("internal", "internal"),
                                                ("external", "external")])
    beacon_id = forms.IntegerField()


@permission_required('cobalt_strike_monitor.add_beaconexclusion')
def create_beacon_exclusion(request):
    form = BeaconExclusionForm(request.POST)
    if form.is_valid():
        original_beacon = Beacon.objects.get(id=form.cleaned_data['beacon_id'])

        if form.cleaned_data['exclusion_type'] == "id":
            obj, _ = BeaconExclusion.objects.get_or_create(**{"beacon_id":
                                                         original_beacon.__getattribute__(form.cleaned_data['exclusion_type'])})
        else:
            obj, _ = BeaconExclusion.objects.get_or_create(**{form.cleaned_data['exclusion_type']:
                                                         original_beacon.__getattribute__(form.cleaned_data['exclusion_type'])})
    else:
        print("invalid beacon exclusion form")

    return redirect('event_tracker:cs-beacons-list')


class BeaconExclusionList(PermissionRequiredMixin, ListView):
    permission_required = 'cobalt_strike_monitor.view_beaconexclusion'
    model = BeaconExclusion


class BeaconExclusionDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'cobalt_strike_monitor.delete_beaconexclusion'
    model = BeaconExclusion

    def get_success_url(self):
        return reverse_lazy('event_tracker:cs-beacon-exclusion-list')


class WebhookListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_webhook'
    model = Webhook


class WebhookCreateView(PermissionRequiredMixin, CreateView):
    permission_required = 'event_tracker.add_webhook'
    model = Webhook
    fields = "__all__"

    def get_success_url(self):
        return reverse_lazy('event_tracker:webhook-list')

    def get_context_data(self, **kwargs):
        context = super(WebhookCreateView, self).get_context_data(**kwargs)
        context["action"] = "Create"
        return context


class WebhookUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = 'event_tracker.change_webhook'
    model = Webhook
    fields = "__all__"

    def get_context_data(self, **kwargs):
        context = super(WebhookUpdateView, self).get_context_data(**kwargs)
        context["action"] = "Update"
        return context


class WebhookDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'event_tracker.delete_webhook'
    model = Webhook

    def get_success_url(self):
        return reverse_lazy('event_tracker:webhook-list')


@permission_required(('event_tracker.add_webhook','event_tracker.change_webhook'))
def trigger_dummy_webhook(request, webhook_id):
    webhook = get_object_or_404(Webhook, pk=webhook_id)
    dummy_ts = TeamServer(description="Dummy Team Server")
    dummy_beacon = Beacon(user="user", computer="computer", process="process.exe", team_server=dummy_ts)
    notify_webhook_new_beacon(webhook, dummy_beacon)

    return redirect(reverse_lazy('event_tracker:webhook-list'))


# --- Team Server Views ---
class BloodhoundServerListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    model = BloodhoundServer
    ordering = ['neo4j_connection_url']

def _get_kerberoastables(tx, system: Optional[str]):
    if system:
        return tx.run("""
            match (n:User) where 
                n.domain = $system and 
                n.hasspn=true  and
                n.enabled=true
            return 
                toLower(n.name) 
            order by n.name""", system=system.upper()).values()
    else:
        return tx.run("""
           match (n:User) where 
                n.hasspn=true and
                n.enabled=true
            return 
                toLower(n.name) 
            order by n.name""").values()
def _get_recent_os_distribution(tx, system: Optional[str], most_recent_machine_login):
    if system:
        return tx.run("match (n:Computer) where n.domain = $system and n.lastlogontimestamp > $most_recent_machine_login - 2628000 return n.operatingsystem as os, count(n.operatingsystem) as freq order by os",
                      system=system.upper(), most_recent_machine_login=most_recent_machine_login).values()
    else:
        return tx.run(
            "match (n:Computer) where n.lastlogontimestamp > $most_recent_machine_login - 2628000 return n.operatingsystem as os, count(n.operatingsystem) as freq order by os desc",
            most_recent_machine_login=most_recent_machine_login).values()


def _get_most_recent_machine_login(tx, system: Optional[str]):
    if system:
        return tx.run("match (n:Computer) where n.domain = $system return max(n.lastlogontimestamp)", system=system.upper()).single()[0]
    else:
        return tx.run("match (n:Computer) return max(n.lastlogontimestamp)").single()[0]


class BloodhoundServerOUView(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    template_name = 'event_tracker/bloodhoundserver_outree.html'


def _get_dn_children(tx, parent):
    # jsTree uses '#' as the root of the tree, switch it to an empty array to make universal logic work
    if parent == ['#']:
        parent = []

    children = tx.run("""
    match (n) where reverse(split(n.distinguishedname, ','))[$parent_len] is not null and 
           reverse(split(n.distinguishedname, ','))[0..$parent_len] = $parent
    return distinct reverse(split(n.distinguishedname, ','))[$parent_len] as nodetext, 
           reverse(split(n.distinguishedname, ','))[0..$node_len] as nodepath,
           count(*) as childcount,
           collect(distinct labels(n)) as labs,
           true in collect(n.owned) as owned
    order by childcount <= 1, toLower(split(nodetext, '=')[-1])""", parent=parent, parent_len=len(parent), node_len=len(parent) + 1)

    return children.fetch(100_000)


class BloodhoundServerOUAPI(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_bloodhoundserver'

    def get(self, request: HttpRequest, *args, **kwargs):
        result = []

        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    children = session.execute_read(_get_dn_children, request.GET["id"].split(","))

                    for nodetext, nodepath, childcount, types, owned in children:
                        try:
                            nodetype = "folder" if childcount > 1 else types[0][0].lower()
                        except:
                            nodetype = "unknown"

                        if owned and nodetype in ['user', 'computer', 'folder']:
                            nodetype += "-owned"

                        result.append({'id': nodepath,
                                       'parent': request.GET["id"],
                                       'text': f"{nodetext}{' (' + str(childcount) + ')' if childcount > 1 or type == 'ou' else ''}",
                                       'children': bool(childcount > 1),
                                       'type': nodetype,
                                       })

        if result:
            return JsonResponse(result, safe=False)
        else:
            return JsonResponse([], safe=False)


def _get_node_by_dn(tx, dn):
    node_rows = tx.run("""match (n) where n.distinguishedname = $dn return n""", dn=dn)
    try:
        return node_rows.fetch(1)[0]['n']
    except:
        return None

class BloodhoundServerNode(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    template_name = 'event_tracker/bloodhoundserver_node.html'

    @xframe_options_exempt
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        node = None
        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    node = session.execute_read(_get_node_by_dn, kwargs["dn"])
                    if node:
                        break

        if not node:
            return None

        dict_version = {}
        for items in node.items():
            dict_version[items[0]] = items[1]

        return {"node_dict": dict_version,
                "dn": kwargs["dn"]}


def _toggle_node_highvalue_by_dn(tx, dn, user):
    return tx.run(
        f'match (n) where n.distinguishedname = $dn set n.highvalue = not n.highvalue, n.highvaluenotes="Marked as High Value by " + $user + " at {datetime.now():%Y-%m-%d %H:%M:%S%z}"',
        dn=dn, user=user)

@permission_required('event_tracker.view_bloodhoundserver')
def toggle_bloodhound_node_highvalue(request, dn):
    for server in BloodhoundServer.objects.filter(active=True).all():
        if driver := get_driver_for(server):
            with driver.session() as session:
                node = session.execute_write(_toggle_node_highvalue_by_dn, dn, request.user.username)

    return redirect(reverse_lazy('event_tracker:bloodhound-node', kwargs={"dn": dn}))

class BloodhoundServerStatsView(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    template_name = 'event_tracker/bloodhoundserver_stats.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        system = None  # Todo make this configurable

        kerberosoatable_hashtypes = [HashCatMode.Kerberos_5_TGSREP_RC4,
                                     HashCatMode.Kerberos_5_TGSREP_AES128,
                                     HashCatMode.Kerberos_5_TGSREP_AES256]

        os_distribution = {}
        kerberoastable_users = {}
        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    try:
                        # Machine OS
                        most_recent_machine_login = session.execute_read(_get_most_recent_machine_login, system)
                        if most_recent_machine_login:
                            results = session.execute_read(_get_recent_os_distribution, system,
                                                           int(most_recent_machine_login))
                            for result in results:
                                if not result[0]:
                                    continue
                                if result[0] not in os_distribution:
                                    os_distribution[result[0]] = 0
                                os_distribution[result[0]] += result[1]
                        # Kerberoastables
                        results = session.execute_read(_get_kerberoastables, system)
                        for result in results:
                            username = result[0].split('@')[0].lower()

                            credential_obj_query = Credential.objects.filter(account=username, hash_type__in=kerberosoatable_hashtypes)
                            if system:
                                credential_obj_query = credential_obj_query.filter(system=system)

                            credential_obj = credential_obj_query.order_by("hash_type").first()
                            kerberoastable_users[username] = credential_obj
                    except Exception as e:
                        print(f"Skipping {server} due to {e}")

        context["os_distribution"] = os_distribution
        context["kerberoastable_users"] = kerberoastable_users
        return context


class BloodhoundServerCreateView(PermissionRequiredMixin, CreateView):
    permission_required = 'event_tracker.add_bloodhoundserver'
    model = BloodhoundServer
    fields = ['neo4j_connection_url', 'neo4j_browser_url', 'username', 'password', 'active']

    def get_success_url(self):
        return reverse_lazy('event_tracker:bloodhound-server-list')

    def get_context_data(self, **kwargs):
        context = super(BloodhoundServerCreateView, self).get_context_data(**kwargs)
        context['action'] = "Create"
        return context


class BloodhoundServerUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = 'event_tracker.change_bloodhoundserver'
    model = BloodhoundServer
    fields = ['neo4j_connection_url', 'neo4j_browser_url', 'username', 'password', 'active']

    def get_success_url(self):
        return reverse_lazy('event_tracker:bloodhound-server-list')

    def get_context_data(self, **kwargs):
        context = super(BloodhoundServerUpdateView, self).get_context_data(**kwargs)
        context['action'] = "Update"
        return context


class BloodhoundServerDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'event_tracker.delete_bloodhoundserver'
    model = BloodhoundServer

    def get_success_url(self):
        return reverse_lazy('event_tracker:bloodhound-server-list')


class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['code', 'name', 'start_date', 'end_date']

    start_date = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "date"}))
    end_date = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "date"}))


class InitialConfigTask(UserPassesTestMixin, CreateView):
    model = Task
    form_class = TaskForm
    template_name = "initial-config/initial-config-task.html"

    def get_success_url(self):
        return reverse_lazy('event_tracker:event-list', kwargs={"task_id": Task.objects.last().pk})

    def test_func(self):
        return not self.model.objects.exists()


class UserPreferencesForm(forms.ModelForm):
    class Meta:
        model = UserPreferences
        fields = ['timezone']


class InitialConfigAdmin(UserPassesTestMixin, CreateView):
    model = User
    form_class = UserCreationForm
    template_name = "initial-config/initial-config-admin.html"

    def get_success_url(self):
        return reverse_lazy('event_tracker:event-list', kwargs={"task_id": Task.objects.last().pk})

    def get_context_data(self, **kwargs):
        context = super(InitialConfigAdmin, self).get_context_data(**kwargs)
        context['preferences_form'] = UserPreferencesForm()
        return context

    def form_valid(self, form):
        result = super(InitialConfigAdmin, self).form_valid(form)
        # Give the new user admin rights
        self.object.is_staff = True
        self.object.is_superuser = True
        self.object.save()
        # Process the timezone form and attach to the new user
        preferences = UserPreferencesForm(self.request.POST).save(commit=False)
        preferences.user = self.object
        preferences.save()
        # Go to the success_url() result
        return result

    def test_func(self):
        return not self.model.objects.exists()


@permission_required('event_tracker.change_event')
def toggle_event_star(request, task_id, pk):
    event = get_object_or_404(Event, pk=pk)
    event.starred = not event.starred
    event.save()
    return HttpResponse(json.dumps({'starred': event.starred}), 'application/json')

@permission_required('event_tracker.change_event')
def toggle_qs_stars(request, task_id):
    eventfilter = EventFilterForm(request.session.get('eventfilter'), task_id=task_id)

    qs = Event.objects.all()

    if eventfilter.is_valid():
        qs = eventfilter.apply_to_queryset(qs)

    if qs.filter(starred=False).exists():
        qs.update(starred=True)
    else:
        qs.update(starred=False)

    return redirect(reverse_lazy("event_tracker:event-list", kwargs={"task_id": task_id}))