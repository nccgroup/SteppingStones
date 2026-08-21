import base64
import io
import itertools
import textwrap
from datetime import timedelta
from math import ceil

import matplotlib
import numpy as np
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import connection
from django.db.models import Min, Max, Q, Count, Case, When, IntegerField, Window, F
from django.db.models.functions import PercentRank
from django.http import HttpResponse, HttpResponseNotFound
from django.shortcuts import get_object_or_404
from django.views import View
from django.views.decorators.csp import csp_override
from matplotlib.cm import ScalarMappable
from matplotlib.figure import Figure
from matplotlib.ticker import PercentFormatter

from event_tracker.models import Task, AttackTactic, AttackSubTechnique, AttackTechnique
from event_tracker.views import MitreEventListView
from event_tracker.views_credentials import badness_colormap, intensity_colormap

Q_DETECTED = Q(detected='FUL') | Q(detected='PAR')
Q_PREVENTED = Q(prevented='FUL') | Q(prevented='PAR')
Q_UNDETECTED = Q(detected='NEG')
Q_UNPREVENTED = Q(prevented='NEG')
Q_DETECTION_UNKNOWN = Q(detected='UNK')


def _grouper(iterable, n, *, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


def _two_dimensional_ones(quantity, width, fillvalue=0.0):
    """
    Builds a 2 dimensional array of quantity * '1.0', with each "row" in the array the size of width. The final
    row will be padded with fillvalue to ensure all rows are the same width.
    """
    result = np.array([1.0] * quantity)
    result = np.pad(result, (0, (width - (quantity % width))), constant_values=fillvalue)
    result = np.reshape(result, (-1, width))
    return result


class GraphicalMitreEventTimelineView(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_event'

    @csp_override({})
    def get(self, request, task_id, **kwargs):
        task = get_object_or_404(Task, id=task_id)
        response = HttpResponse(content_type='image/png')
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
        fig = Figure()
        ax = fig.subplots()

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

        ax.set_title("MITRE Event Timeline")
        ax.grid(axis="y")
        ax.xaxis.set_tick_params(labelrotation=45/2)

        start, end = date_range["start"], date_range["end"]
        span_days = (end - start).days
        if span_days >= 14:
            # Find the first Monday on or after start
            days_until_monday = (7 - start.weekday()) % 7
            first_monday = start + timedelta(days=days_until_monday)
            mondays = []
            monday = first_monday
            while monday < end:
                mondays.append(monday)
                monday += timedelta(weeks=1)
            ticks = sorted({start, *mondays, end})
            ax.set_xticks(ticks)

        fig.tight_layout()

        fig.savefig(response, dpi=300)
        return response


class GraphicalDailyDetectionsAndPreventionsView(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_event'

    @csp_override({})
    def get(self, request, task_id, **kwargs):
        task = get_object_or_404(Task, id=task_id)
        response = HttpResponse(content_type='image/png')

        matplotlib.rcParams['font.size'] = 8.0

        exercise_days = task.event_set.dates("timestamp", "day")

        fig = Figure()
        ax = fig.subplots()

        labels = []
        neither_detected_nor_prevented = []
        unprevented_detection_unknown = []
        detected_only = []
        prevented_only = []
        prevented_detection_unknown = []
        both_detected_and_prevented = []

        for day in exercise_days:
            day_summary = task.event_set.filter(timestamp__date=day).aggregate(
                neither_detected_nor_prevented=Count(Case(
                    When(Q_UNDETECTED & Q_UNPREVENTED, then=1),
                    output_field=IntegerField(),
                )),
                unprevented_detection_unknown=Count(Case(
                    When(Q_DETECTION_UNKNOWN & Q_UNPREVENTED, then=1),
                    output_field=IntegerField(),
                )),
                detected_only=Count(Case(
                        When(Q_DETECTED & Q_UNPREVENTED, then=1),
                        output_field=IntegerField(),
                    )),
                prevented_only=Count(Case(
                    When(Q_UNDETECTED & Q_PREVENTED, then=1),
                    output_field=IntegerField(),
                )),
                prevented_detection_unknown=Count(Case(
                    When(Q_DETECTION_UNKNOWN & Q_PREVENTED, then=1),
                    output_field=IntegerField(),
                )),
                both_detected_and_prevented=Count(Case(
                    When(Q_DETECTED & Q_PREVENTED, then=1),
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
                When(Q_UNDETECTED & Q_UNPREVENTED, then=1),
                output_field=IntegerField(),
            )),
            unprevented_detection_unknown=Count(Case(
                When(Q_DETECTION_UNKNOWN & Q_UNPREVENTED, then=1),
                output_field=IntegerField(),
            )),
            detected_only=Count(Case(
                    When(Q_DETECTED & Q_UNPREVENTED, then=1),
                    output_field=IntegerField(),
                )),
            prevented_only=Count(Case(
                When(Q_UNDETECTED & Q_PREVENTED, then=1),
                output_field=IntegerField(),
            )),
            prevented_detection_unknown=Count(Case(
                When(Q_DETECTION_UNKNOWN & Q_PREVENTED, then=1),
                output_field=IntegerField(),
            )),
            both_detected_and_prevented=Count(Case(
                When(Q_DETECTED & Q_PREVENTED, then=1),
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

        ax.set_title("Daily Detections and Preventions")
        ax.legend()
        ax.xaxis.set_tick_params(labelrotation=45/2)

        fig.savefig(response, dpi=300)
        return response


def _render_heatmap(tactic_cells, colormap, colorbar_kwargs):
    """
    Render a MITRE heatmap figure given pre-built cell data.

    tactic_cells: dict mapping each tactic to a list of (obj, score) pairs,
                  where score is a float in [0, 1] for the colormap.
    colormap: matplotlib colormap to use for cell colours.
    colorbar_kwargs: extra kwargs forwarded to fig.colorbar().
    """
    # Drop any tactic that produced no cells (e.g. event has tactic but no technique set)
    tactic_cells = {tactic: cells for tactic, cells in tactic_cells.items() if cells}

    subplot_heights = [0.4, 0.1]
    for tactic, cells in tactic_cells.items():
        subplot_heights.append(ceil(len(cells) / 4))

    figure_height_inches = ((np.sum(subplot_heights) * 3) + len(tactic_cells)) / 3 + 0.9
    fig = Figure(figsize=(10, figure_height_inches))
    ax = fig.subplots(ncols=1, nrows=len(tactic_cells) + 2, height_ratios=subplot_heights)

    fig.colorbar(ScalarMappable(cmap=colormap), cax=fig.get_axes()[0],
                 orientation="horizontal", **colorbar_kwargs)
    ax[1].set_axis_off()

    for plot_num, (tactic, cells) in enumerate(tactic_cells.items()):
        current_axes = ax[plot_num + 2]  # Add +2 offset for axis used by colorbar

        scores = [score for _, score in cells]
        grid = np.array(list(_grouper(scores, 4, fillvalue=0.0)))

        current_axes.imshow(grid, cmap=colormap, aspect='auto',
                            alpha=_two_dimensional_ones(len(scores), 4),
                            vmin=0, vmax=1)  # Need to scale with vmin/vmax of the overall dataset, else just scales across range of grid

        current_axes.set_xticks(np.arange(grid.shape[1] + 1) - .5, minor=False, labels="")
        current_axes.set_yticks(np.arange(grid.shape[0] + 1) - .5, minor=False, labels="")
        current_axes.tick_params(length=0)
        current_axes.grid(True, which="major", color='black', linestyle='-', markevery=1)

        for idx, (obj, score) in enumerate(cells):
            i, j = divmod(idx, 4)
            title_text = '\n'.join(textwrap.wrap(obj.name, width=20))
            current_axes.text(j, i, f"{obj.mitre_id}\n{title_text}",
                              ha="center", va="center", fontsize=12)

        current_axes.set_title(tactic)

    fig.tight_layout()
    fig.subplots_adjust(hspace=0.6)
    return fig


class GraphicalMitreActivityHeatMapEventListView(MitreEventListView):
    template_name = 'mitre_activity_heat_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        include_subtechniques = ("include_subtechniques" in self.kwargs and
                                 self.kwargs["include_subtechniques"] == 'include_subtechniques')
        context["include_subtechniques"] = include_subtechniques

        if include_subtechniques:
            value_columns = ['mitre_attack_tactic_id', "mitre_attack_technique_id", "mitre_attack_subtechnique_id"]
        else:
            value_columns = ['mitre_attack_tactic_id', "mitre_attack_technique_id"]

        percentiles = self.get_queryset().values(*value_columns).annotate(
                icount=Count('*'),
                percent_rank=Window(
                    expression=PercentRank(),
                    order_by=[F("icount").asc(), ]
            ))

        fig = self.generate_activity_heatmap(context["event_tactics"], percentiles, include_subtechniques)

        buffer = io.BytesIO()
        fig.savefig(buffer, format='png')
        buffer.seek(0)
        context['heatmap_b64'] = base64.b64encode(buffer.read()).decode("ASCII")

        return context

    def generate_activity_heatmap(self, tactics, percentiles, include_subtechniques):
        if include_subtechniques:
            sort_columns = ["mitre_attack_technique_id", "mitre_attack_subtechnique_id"]
        else:
            sort_columns = ["mitre_attack_technique_id"]

        tactic_cells = {}
        for tactic in tactics:
            # Use raw SQL to do a nested query from the WHOLE dataset, because filtering the percentile queryset inline
            # skews the statistics because the window they are calculated over is only the filtered data
            sql, params = percentiles.query.sql_with_params()
            with connection.cursor() as cursor:
                cursor.execute(
                    f'SELECT percent_rank FROM ({sql}) WHERE mitre_attack_tactic_id=%s ORDER BY {", ".join(sort_columns)}',
                    (*params, tactic.id)
                )
                percentile_values = list(itertools.chain.from_iterable(cursor.fetchall()))

            percentiles_for_tactic = percentiles.filter(mitre_attack_tactic_id=tactic.id).order_by(*sort_columns)

            cells = []
            for row, score in zip(percentiles_for_tactic, percentile_values):
                if "mitre_attack_subtechnique_id" in row and row["mitre_attack_subtechnique_id"]:
                    obj = AttackSubTechnique.objects.get(pk=row["mitre_attack_subtechnique_id"])
                elif "mitre_attack_technique_id" in row and row["mitre_attack_technique_id"]:
                    obj = AttackTechnique.objects.get(pk=row["mitre_attack_technique_id"])
                else:
                    obj = tactic
                cells.append((obj, score))
            tactic_cells[tactic] = cells

        colorbar_kwargs = {"format": PercentFormatter(xmax=1), "label": "Number of attempts (as percentile)"}
        return _render_heatmap(tactic_cells, intensity_colormap, colorbar_kwargs)


class GraphicalMitreDetectionPreventionHeatMapEventListView(MitreEventListView):
    template_name = 'mitre_detection_prevention_heat_map.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        include_subtechniques = ("include_subtechniques" in self.kwargs and
                                 self.kwargs["include_subtechniques"] == 'include_subtechniques')
        context["include_subtechniques"] = include_subtechniques

        fig = self.generate_detection_prevention_heatmap(context["event_tactics"], include_subtechniques)

        buffer = io.BytesIO()
        fig.savefig(buffer, format='png')
        buffer.seek(0)
        context['heatmap_b64'] = base64.b64encode(buffer.read()).decode("ASCII")

        return context

    def _mode_score_for_ttp(self, qs):
        """
        Return the modal badness score for all events in qs.
        Scores: 0.0, 0.2, 0.4, 0.6, 0.8, 1.0
        """
        counts = qs.aggregate(
            both=Count(Case(When(Q_DETECTED & Q_PREVENTED, then=1), output_field=IntegerField())),
            prev_unk=Count(Case(When(Q_DETECTION_UNKNOWN & Q_PREVENTED, then=1), output_field=IntegerField())),
            prev_only=Count(Case(When(Q_UNDETECTED & Q_PREVENTED, then=1), output_field=IntegerField())),
            det_only=Count(Case(When(Q_DETECTED & Q_UNPREVENTED, then=1), output_field=IntegerField())),
            unk_unprev=Count(Case(When(Q_DETECTION_UNKNOWN & Q_UNPREVENTED, then=1), output_field=IntegerField())),
            neither=Count(Case(When(Q_UNDETECTED & Q_UNPREVENTED, then=1), output_field=IntegerField())),
        )

        # Pick the category with the highest count; ties broken in favour of worse score
        return max(
            [(counts['both'], 1.0), (counts['prev_unk'], 0.8), (counts['prev_only'], 0.6),
             (counts['det_only'], 0.4), (counts['unk_unprev'], 0.2), (counts['neither'], 0.0)],
            key=lambda x: (x[0], -x[1])
        )[1]

    def generate_detection_prevention_heatmap(self, tactics, include_subtechniques):
        events = self.get_queryset()

        tactic_cells = {}
        for tactic, techniques in tactics.items():
            cells = []
            if include_subtechniques:
                for technique, subtechniques in techniques.items():
                    subs = list(subtechniques.order_by("mitre_id"))
                    if subs:
                        for sub in subs:
                            qs = events.filter(mitre_attack_tactic=tactic,
                                               mitre_attack_technique=technique,
                                               mitre_attack_subtechnique=sub)
                            cells.append((sub, self._mode_score_for_ttp(qs)))
                    else:
                        qs = events.filter(mitre_attack_tactic=tactic,
                                           mitre_attack_technique=technique,
                                           mitre_attack_subtechnique__isnull=True)
                        cells.append((technique, self._mode_score_for_ttp(qs)))
            else:
                for technique in sorted(techniques.keys(), key=lambda t: t.mitre_id):
                    qs = events.filter(mitre_attack_tactic=tactic,
                                       mitre_attack_technique=technique)
                    cells.append((technique, self._mode_score_for_ttp(qs)))
            tactic_cells[tactic] = cells

        colorbar_kwargs = {
            "ticks": [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
            "label": "Modal detection/prevention outcome",
        }
        fig = _render_heatmap(tactic_cells, badness_colormap, colorbar_kwargs)
        fig.get_axes()[0].set_xticklabels([
            "Neither", "Unprevented\n(Det. Unknown)", "Detected\nOnly",
            "Prevented\nOnly", "Prevented\n(Det. Unknown)", "Both Det.\n& Prev."
        ], fontsize=6)
        return fig
