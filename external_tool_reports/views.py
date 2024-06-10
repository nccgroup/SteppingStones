import io

import xlsxwriter
from django import forms
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.core.signing import TimestampSigner
from django.db.models import Min, Max
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.template import loader
from django.utils.http import urlencode
from django.views import View
from django.views.generic import TemplateView
from taggit.models import Tag

from event_tracker.models import AttackTactic, Task, Event
from event_tracker.templatetags.custom_tags import firstsentence

from event_tracker.views import EventListView


# Create your views here.
class OfficeTimelineExportForm(forms.Form):
    CHOICES = [
        ('1', 'Event titles are first sentence of Description'),
        ('2', 'Event titles are first sentence of Outcome'),
    ]
    event_titles = forms.ChoiceField(
        widget=forms.RadioSelect,
        choices=CHOICES,
        initial=2,
        label=" ",  # Something non-empty in order to have a label rendered and the radio buttons pushed right accordingly
    )
    include_tags = forms.BooleanField(label="Include Tag timespans", required=False, initial=True)
    include_mitre_tactics = forms.BooleanField(label="Include MITRE Tactic timespans", required=False, initial=False)


class OfficeTimelineExportOptions(PermissionRequiredMixin, TemplateView):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')
    template_name = 'office_timeline_export.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context["task_id"] = kwargs.pop("task_id", 1)
        context["export_options"] = OfficeTimelineExportForm()

        return context


class OfficeTimelineExportGenerate(EventListView):
    def get(self, request, *args, **kwargs):
        excel_date_format = "%Y-%m-%d"

        # Create an in-memory output file for the new workbook.
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output)
        worksheet = workbook.add_worksheet()

        worksheet.write_row(0, 0, ("Row ID", "Swimlane", "Title", "Start date", "End date"))

        options = OfficeTimelineExportForm(request.GET)
        if options.is_valid():
            row = 1

            if options.cleaned_data["event_titles"] == '1':
                event_qs = self.get_queryset().filter(description__isnull=False).exclude(description__exact="")
            else:
                event_qs = self.get_queryset().filter(outcome__isnull=False).exclude(outcome__exact="")

            for event in event_qs:
                worksheet.write(row, 0, event.pk)  # Unique ID for the row
                worksheet.write(row, 1, "Events")  # Swimlane
                if options.cleaned_data["event_titles"] == '1':
                    worksheet.write(row, 2, firstsentence(event.description))  # First sentence of the description
                else:
                    worksheet.write(row, 2, firstsentence(event.outcome))  # First sentence of the outcome
                worksheet.write(row, 3, event.timestamp.strftime(excel_date_format))
                if event.timestamp_end and event.timestamp_end.strftime(excel_date_format) != event.timestamp.strftime(excel_date_format):
                    worksheet.write(row, 4, event.timestamp_end.strftime(excel_date_format))
                row += 1

            if options.cleaned_data["include_mitre_tactics"]:
                for tactic in AttackTactic.objects.filter(pk__in=self.get_queryset().values("mitre_attack_tactic")):
                    tactic_data = self.get_queryset().filter(mitre_attack_tactic=tactic).aggregate(min=Min("timestamp"), max=Max("timestamp"))

                    worksheet.write(row, 0, tactic.mitre_id)  # Unique ID for the row
                    worksheet.write(row, 1, "MITRE Tactics")  # Swimlane
                    worksheet.write(row, 2, str(tactic))
                    worksheet.write(row, 3, tactic_data['min'].strftime(excel_date_format))
                    if tactic_data['min'].strftime(excel_date_format) != tactic_data['max'].strftime(excel_date_format):
                        worksheet.write(row, 4, tactic_data['max'].strftime(excel_date_format))
                    row += 1

            if options.cleaned_data["include_tags"]:
                for tag in Tag.objects.all():
                    tag_data = self.get_queryset().filter(tags__name__in=[tag.name]).aggregate(min=Min("timestamp"),
                                                                                                   max=Max("timestamp"))

                    worksheet.write(row, 0, f"Tag_{tag.pk}")  # Unique ID for the row
                    worksheet.write(row, 1, "Tags")  # Swimlane
                    worksheet.write(row, 2, tag.name)
                    worksheet.write(row, 3, tag_data['min'].strftime(excel_date_format))
                    if tag_data['min'].strftime(excel_date_format) != tag_data['max'].strftime(excel_date_format):
                        worksheet.write(row, 4, tag_data['max'].strftime(excel_date_format))
                    row += 1

        # Close the workbook before sending the data.
        workbook.close()

        # Rewind the buffer.
        output.seek(0)

        response = HttpResponse(output, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="officetimeline.xlsx"'
        return response


class MITREAttackNavigatorView(PermissionRequiredMixin, View):
    permission_required = ('event_tracker.view_reports', 'event_tracker.view_event')

    def has_permission(self):
        signer = TimestampSigner()

        if 'sig' in self.request.GET \
                and signer.unsign(self.request.GET.get('sig'), max_age=10) == self.request.build_absolute_uri().split("?")[0]:
            return True
        else:
            return super().has_permission()

    def get(self, request, task_id, **kwargs):
        # An authenticated user generates a signed URL with 10 seconds expiry and redirects to the MITRE Attack Navigator
        # to load that signed URL

        if 'sig' in request.GET:
            # To have gotten this far, the PermissionRequiredMixin will have verified the sig
            task = get_object_or_404(Task, id=task_id)

            unused_techniques = dict()
            unused_subtechniques = dict()
            for tactic in AttackTactic.objects.all():
                unused_techniques[tactic.shortname] = tactic.attacktechnique_set.\
                    exclude(id__in=Event.objects.filter(mitre_attack_tactic=tactic, mitre_attack_technique__isnull=False).values_list('mitre_attack_technique__id', flat=True)).\
                    values_list('mitre_id', flat=True)
                for technique in tactic.attacktechnique_set.all():
                    if tactic.shortname not in unused_subtechniques:
                        unused_subtechniques[tactic.shortname] = list()
                    unused_subtechniques[tactic.shortname] += (technique.attacksubtechnique_set.\
                        exclude(id__in=Event.objects.filter(mitre_attack_tactic=tactic, mitre_attack_subtechnique__isnull=False).values_list('mitre_attack_subtechnique__id', flat=True)).\
                        values_list('mitre_id', flat=True))

            template_vars = {
                "events": task.event_set.all(),
                "name": task.name,
                "unused_techniques": unused_techniques,
                "unused_subtechniques": unused_subtechniques,
            }

            response = HttpResponse(content_type='application/json')

            response['Access-Control-Allow-Origin'] = "https://mitre-attack.github.io"

            template = loader.get_template("navigator_layer.json")
            response.content = template.render(template_vars)
            return response

        else:
            # Will have only got this far if no sig but met any other access requirements, so
            # Generate sig and forward to MITRE
            signer = TimestampSigner()
            sig = signer.sign(request.build_absolute_uri())

            return redirect("https://mitre-attack.github.io/attack-navigator/#"
                            + urlencode({"layerURL": request.build_absolute_uri() + "?sig=" + sig}))
