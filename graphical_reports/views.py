import base64
import io
import itertools
import textwrap
from datetime import timedelta
from math import ceil

import matplotlib
import numpy as np
from csp.decorators import csp_exempt
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import connection
from django.db.models import Min, Max, Q, Count, Case, When, IntegerField, Window, F
from django.db.models.functions import PercentRank
from django.http import HttpResponse, HttpResponseNotFound
from django.shortcuts import get_object_or_404
from django.views import View
from matplotlib import pyplot as plt
from matplotlib.cm import ScalarMappable
from matplotlib.ticker import PercentFormatter

from event_tracker.models import Task, AttackTactic, AttackSubTechnique, AttackTechnique
from event_tracker.views import MitreEventListView
from event_tracker.views_credentials import badness_colormap, intensity_colormap

matplotlib.use('agg')

class GraphicalMitreEventTimelineView(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_event'

    def get(self, request, task_id, **kwargs):
        task = get_object_or_404(Task, id=task_id)
        response = HttpResponse(content_type='image/png')
        response._csp_exempt = True
        matplotlib.rcParams['font.size'] = 8.0

        labels = []
        data = []

        for tactic in AttackTactic.objects.all():
            events_for_tactic = task.event_set.filter(mitre_attack_tactic=tactic)
            if events_for_tactic.exists():
                labels.insert(0, tactic.mitre_id + "\n" + tactic.name)

                data.insert(0, [event.timestamp for event in events_for_tactic.all()])

        if not data:
            return HttpResponseNotFound('No events tagged with MITRE references')

        # set different colors for each set of positions
        colors1 = [f'C{i}' for i in range(len(labels))]

        # create a horizontal plot
        fig, ax = plt.subplots()

        # Add bands for each weekend day in the range
        date_range = task.event_set.all().aggregate(start=Min("timestamp"), end=Max("timestamp"))
        date_it = date_range["start"]
        while date_it < date_range["end"]:
            if date_it.weekday() >= 5:  # Mon = 0 .. Sat = 5, Sun = 6
                ax.axvspan(date_it.replace(hour=0, minute=0, second=0),
                           date_it.replace(hour=23, minute=59, second=59),
                           facecolor='black', alpha=.2)
            date_it += timedelta(days=1)

        ax.eventplot(data, colors=colors1, lineoffsets=labels)

        ax.grid(axis="y")
        plt.xticks(rotation=45/2)
        plt.tight_layout()

        plt.savefig(response, dpi=300, transparent=True)
        return response


class GraphicalDailyDetectionsAndPreventionsView(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_event'

    def get(self, request, task_id, **kwargs):
        task = get_object_or_404(Task, id=task_id)
        response = HttpResponse(content_type='image/png')
        response._csp_exempt = True

        matplotlib.rcParams['font.size'] = 8.0

        exercise_days = task.event_set.dates("timestamp", "day")

        fig, ax = plt.subplots()

        labels = []
        neither_detected_nor_prevented = []
        unprevented_detection_unknown = []
        detected_only = []
        prevented_only = []
        prevented_detection_unknown = []
        both_detected_and_prevented = []

        detected = Q(detected='FUL') | Q(detected='PAR')
        prevented = Q(prevented='FUL') | Q(prevented='PAR')
        not_detected = Q(detected='NEG')
        not_prevented = Q(prevented='NEG')
        detection_unknown = Q(detected='UNK')

        for day in exercise_days:
            day_summary = task.event_set.filter(timestamp__date=day).aggregate(
                neither_detected_nor_prevented=Count(Case(
                    When(not_detected & not_prevented, then=1),
                    output_field=IntegerField(),
                )),
                unprevented_detection_unknown=Count(Case(
                    When(detection_unknown & not_prevented, then=1),
                    output_field=IntegerField(),
                )),
                detected_only=Count(Case(
                        When(detected & not_prevented, then=1),
                        output_field=IntegerField(),
                    )),
                prevented_only=Count(Case(
                    When(not_detected & prevented, then=1),
                    output_field=IntegerField(),
                )),
                prevented_detection_unknown=Count(Case(
                    When(detection_unknown & prevented, then=1),
                    output_field=IntegerField(),
                )),
                both_detected_and_prevented=Count(Case(
                    When(detected & prevented, then=1),
                    output_field=IntegerField(),
                )),
                total_events=Count("*"),
            )

            labels.append(str(day))
            neither_detected_nor_prevented.append(day_summary["neither_detected_nor_prevented"])
            unprevented_detection_unknown.append(day_summary["unprevented_detection_unknown"])
            detected_only.append(day_summary["detected_only"])
            prevented_only.append(day_summary["prevented_only"])
            prevented_detection_unknown.append(day_summary["prevented_detection_unknown"])
            both_detected_and_prevented.append(day_summary["both_detected_and_prevented"])

        total_summary = task.event_set.aggregate(
            neither_detected_nor_prevented=Count(Case(
                When(not_detected & not_prevented, then=1),
                output_field=IntegerField(),
            )),
            unprevented_detection_unknown=Count(Case(
                When(detection_unknown & not_prevented, then=1),
                output_field=IntegerField(),
            )),
            detected_only=Count(Case(
                    When(detected & not_prevented, then=1),
                    output_field=IntegerField(),
                )),
            prevented_only=Count(Case(
                When(not_detected & prevented, then=1),
                output_field=IntegerField(),
            )),
            prevented_detection_unknown=Count(Case(
                When(detection_unknown & prevented, then=1),
                output_field=IntegerField(),
            )),
            both_detected_and_prevented=Count(Case(
                When(detected & prevented, then=1),
                output_field=IntegerField(),
            )),
            total_events=Count("*"),
        )

        width = 0.7

        ax.bar(labels, both_detected_and_prevented, width, label=f"Both Detected and Prevented {(total_summary['both_detected_and_prevented'] / total_summary['total_events']):.2%}",
               bottom=[sum(x) for x in zip(neither_detected_nor_prevented, unprevented_detection_unknown, detected_only, prevented_only, prevented_detection_unknown)], color=badness_colormap(1.0))
        ax.bar(labels, prevented_detection_unknown, width,
               label=f"Prevented (Detection Unknown) {(total_summary['prevented_detection_unknown'] / total_summary['total_events']):.2%}",
               bottom=[sum(x) for x in zip(neither_detected_nor_prevented, unprevented_detection_unknown, detected_only, prevented_only)],
               color=badness_colormap(0.8))
        ax.bar(labels, prevented_only, width, label=f"Prevented Only {(total_summary['prevented_only'] / total_summary['total_events']):.2%}",
               bottom=[sum(x) for x in zip(neither_detected_nor_prevented, unprevented_detection_unknown, detected_only)], color=badness_colormap(0.6))
        ax.bar(labels, detected_only, width, label=f"Detected Only {(total_summary['detected_only'] / total_summary['total_events']):.2%}", bottom=[sum(x) for x in zip(neither_detected_nor_prevented, unprevented_detection_unknown)], color=badness_colormap(0.4))
        ax.bar(labels, unprevented_detection_unknown, width,
               label=f"Unprevented (Detection Unknown) {(total_summary['unprevented_detection_unknown'] / total_summary['total_events']):.2%}",
               bottom=neither_detected_nor_prevented, color=badness_colormap(0.2))
        ax.bar(labels, neither_detected_nor_prevented, width, label=f"Neither Detected Nor Prevented {(total_summary['neither_detected_nor_prevented'] / total_summary['total_events']):.2%}", color=badness_colormap(0.0))

        ax.legend()
        plt.xticks(rotation=45/2)

        plt.savefig(response, dpi=300, transparent=True)
        return response


class GraphicalMitreHeatMapEventListView(MitreEventListView):
    template_name = 'mitre_heat_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        include_subtechniques = ("include_subtechniques" in self.kwargs and
                                 self.kwargs["include_subtechniques"] == 'include_subtechniques')
        context["include_subtechniques"] = include_subtechniques

        if include_subtechniques:
            value_columns = ['mitre_attack_tactic', "mitre_attack_technique", "mitre_attack_subtechnique"]
        else:
            value_columns = ['mitre_attack_tactic', "mitre_attack_technique"]

        percentiles = self.get_queryset().values(*value_columns).annotate(
                icount=Count('*'),
                percent_rank=Window(
                    expression=PercentRank(),
                    order_by=[F("icount").asc(), ]
            ))

        plt = self.generate_heatmap(context["event_tactics"], percentiles, include_subtechniques)

        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        context['heatmap_b64'] = base64.b64encode(buffer.read()).decode("ASCII")

        return context

    def grouper(self, iterable, n, *, fillvalue=None):
        args = [iter(iterable)] * n
        return itertools.zip_longest(*args, fillvalue=fillvalue)

    def two_dimensional_ones(self, quantity, width, fillvalue=0.0):
        """
        Builds a 2 dimensional array of quantity * '1.0', with each "row" in the array the size of width. The final
        row will be padded with fillvalue to ensure all rows are the same width.
        """
        result = np.array([1.0] * quantity)
        result = np.pad(result, (0, (width - (quantity % width))), constant_values=fillvalue)
        result = np.reshape(result, (-1, width))

        return result

    def generate_heatmap(self, tactics, percentiles, include_subtechniques):
        if include_subtechniques:
            sort_columns = ["mitre_attack_technique_id", "mitre_attack_subtechnique_id"]
        else:
            sort_columns = ["mitre_attack_technique_id"]

        # Calculate height of each subplot
        subplot_heights = [.4, 0.1]  # Height of the colorbar's subplot

        for tactic in tactics:
            cells_for_tactic = percentiles.filter(mitre_attack_tactic_id=tactic.id).count()
            subplot_heights.append(ceil(cells_for_tactic / 4))

        # Define main "figure" (i.e. canvas)
        figure_height_inches = ((np.sum(subplot_heights) * 3) + len(tactics)) / 3 + 0.9

        fig, ax = plt.subplots(ncols=1, nrows=len(tactics) + 2,
                               figsize=(10, figure_height_inches), height_ratios=subplot_heights)

        plt.colorbar(ScalarMappable(cmap=intensity_colormap), cax=fig.get_axes()[0], orientation="horizontal", format=PercentFormatter(xmax=1))
        ax[0].set_title("Key: Number of attempts (as percentile)")
        ax[1].set_axis_off()

        # Each tactic's subplot
        for plot_num, tactic in enumerate(tactics):
            current_axes = ax[plot_num + 2]  # Add +2 offset for axis used by for colorbar

            # Use raw SQL to do a nested query from the WHOLE dataset, because filtering the percentile queryset inline
            # skews the statistics because the window they are calculated over is only the filtered data
            sql, params = percentiles.query.sql_with_params()
            with connection.cursor() as cursor:
                cursor.execute(
                    f'SELECT percent_rank FROM ({sql}) WHERE mitre_attack_tactic_id=={tactic.id} ORDER BY {", ".join(sort_columns)}',
                    params
                )
                percentile_values = list(itertools.chain.from_iterable(cursor.fetchall()))

            percentiles_for_tactic = percentiles.filter(mitre_attack_tactic_id=tactic.id).order_by(*sort_columns)

            grid = np.array(list(self.grouper(percentile_values, 4, fillvalue=0.0)))

            current_axes.imshow(grid, cmap=intensity_colormap, aspect='auto', alpha=self.two_dimensional_ones(len(percentile_values), 4),
                                vmin=0, vmax=1)  # Need to scale with vmin/vmax of the overall dataset, else just scales across range of grid

            current_axes.set_xticks(np.arange(grid.shape[1] + 1) - .5, minor=False, labels="")
            current_axes.set_yticks(np.arange(grid.shape[0] + 1) - .5, minor=False, labels="")
            current_axes.tick_params(length=0)
            current_axes.grid(True, which="major", color='black', linestyle='-', markevery=1)

            # Loop over data dimensions and create text annotations.
            iterator = percentiles_for_tactic.iterator()
            for i in range(len(grid)):
                for j in range(len(grid[0])):
                    try:
                        row = next(iterator)
                        suffix = ""
                        if "mitre_attack_subtechnique" in row and row["mitre_attack_subtechnique"]:
                            object = AttackSubTechnique.objects.get(pk=row["mitre_attack_subtechnique"])
                        elif "mitre_attack_technique" in row and row["mitre_attack_technique"]:
                            object = AttackTechnique.objects.get(pk=row["mitre_attack_technique"])
                        else:
                            object = tactic
                            suffix = "\n[Uncategorised]"

                        title_text = '\n'.join(textwrap.wrap(object.name, width = 20))
                        current_axes.text(j, i, f"{object.mitre_id}\n{title_text}{suffix}",
                                          ha="center", va="center", fontsize=12)
                    except StopIteration:
                        break

            current_axes.set_title(tactic)

        fig.tight_layout()

        plt.subplots_adjust(hspace=0.6)

        return plt
