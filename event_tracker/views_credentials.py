import contextlib
import csv
import io
import itertools
import re
import time
from datetime import datetime

import numpy as np
from django import forms
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.db.models import Count, Max, Subquery, F, Case, When, Value, Q, ExpressionWrapper, FloatField, OuterRef
from django.db.models.functions import Lower, Length, Cast
from django.forms import BooleanField, Textarea
from django.http import HttpResponse, HttpResponseNotFound, StreamingHttpResponse
from django.shortcuts import redirect
from django.template.defaultfilters import truncatechars_html
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.html import escape
from django.views.generic import FormView, ListView, CreateView, UpdateView, DeleteView, TemplateView
from django_datatables_view.base_datatable_view import BaseDatatableView
from djangoplugins.models import ENABLED
from matplotlib.colors import LinearSegmentedColormap, to_rgba_array
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator
from neo4j.exceptions import ClientError

from event_tracker.cred_extractor import EMPTY_LMHASH, EMPTY_NTLMHASH
from event_tracker.models import Credential, HashCatMode, BloodhoundServer
from event_tracker.plugins import CredentialReportingPluginPoint
from event_tracker.signals import get_driver_for, extract_creds
from event_tracker.templatetags.custom_tags import breakonpunctuation, hash_type_name

import duckdb

INFO_COLOR = "#E9F3F1"
GOOD_COLOR = "#AFF6CD"
LOW_RISK_COLOR = "#F7F4B9"
MEDIUM_RISK_COLOR = "#F7D089"
HIGH_RISK_COLOR = "#E97590"
CRITICAL_RISK_COLOR = "#C881EC"
UNKNOWN_COLOR = "#CDCDCD"
badness_colormap = LinearSegmentedColormap.from_list("mycmap", [HIGH_RISK_COLOR, MEDIUM_RISK_COLOR, LOW_RISK_COLOR, GOOD_COLOR])
intensity_colormap = LinearSegmentedColormap.from_list("mycmap", [INFO_COLOR, LOW_RISK_COLOR, MEDIUM_RISK_COLOR, HIGH_RISK_COLOR, CRITICAL_RISK_COLOR])

SYMBOLS = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
DIGITS = "0123456789"

SYMBOL_REGEX = "[[:punct:] ]+"
DIGIT_REGEX = "[0-9]"


class CredentialSystemFilter(forms.Form):
    enabled = BooleanField(widget=forms.CheckboxInput(attrs={'class': 'submit-on-change'}), required=False, initial=False)
    plot_uncracked = BooleanField(widget=forms.CheckboxInput(attrs={'class': 'submit-on-change'}), required=False, initial=False)

    class Media:
        js = ["scripts/ss-forms.js"]

    def __init__(self, **kwargs):
        super(CredentialSystemFilter, self).__init__(**kwargs)

        systems = Credential.objects.filter(system__isnull=False).annotate(syslower=Lower("system")).values("syslower").annotate(syscount=Count("syslower")).order_by("-syscount")
        total_credentials = Credential.objects.count()

        choices = [('', f"All systems ({total_credentials} credential{'s' if total_credentials != 1 else ''})")]
        choices += list(zip(systems.values_list("syslower", flat=True),
                                  [f"{row['syslower']} ({row['syscount']} credential{'s' if row['syscount'] != 1 else ''})" for row in systems]))
        self.fields['system'] = forms.ChoiceField(choices=choices, required=False,
                                                  widget=forms.Select(attrs={'class': 'form-select form-select-sm submit-on-change'}))


class CredentialStatsView(PermissionRequiredMixin, FormView):
    permission_required = 'event_tracker.view_credential'
    template_name = "event_tracker/credential_stats.html"
    form_class = CredentialSystemFilter

    def get_initial(self):
        """
        Merge the session stored filter into the form's initial state
        """
        initial = super().get_initial()
        initial.update(self.request.session.get("credentialstatsfilter", default={}))
        return initial

    def form_valid(self, form):
        self.request.session['credentialstatsfilter'] = form.cleaned_data
        return self.render_to_response(self.get_context_data())

    @staticmethod
    def _has_bloodhound_users(tx, system):
        if system:
            query = "MATCH (n:User) where (toLower(n.domain) = toLower($system)) return 1 limit 1"
        else:
            query = "MATCH (n:User) return 1 limit 1"
        return tx.run(query, system=system).single() is not None

    @staticmethod
    def _bucket_password_ages(tx, system, enabled):
        query = "MATCH (n:User) where " + \
                      ("toLower(n.domain) = toLower($system) and " if system else "") +\
                 """
                 n.pwdlastset is not null and 
                 n.pwdlastset > 0 """ + ("and n.enabled=True " if enabled else "") +\
               """return duration.between(datetime({epochSeconds:toInteger(n.pwdlastset)}), datetime()).years as years, count(*) as count order by years"""

        return tx.run(query, system=system).values()

    @staticmethod
    def _oldest_password_ages(tx, system, enabled):
        query = f"""MATCH (n:User) WHERE 
                       {"toLower(n.domain) = toLower($system) and " if system else ""}
                       n.pwdlastset is not null and 
                       n.pwdlastset > 0 {"and n.enabled=True " if enabled else ""}
                    RETURN {"n.samaccountname" if system else "n.name"}, 
                       datetime({{epochSeconds:toInteger(n.pwdlastset)}}), 
                       datetime({{epochSeconds:toInteger(n.lastlogontimestamp)}}),
                       n.lastlogontimestamp
                    ORDER BY n.pwdlastset
                    LIMIT 10"""

        return tx.run(query, system=system).values()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        credential_per_cracked_account, _, filtered_creds, ids_of_unqiue_accounts, system, enabled, _ = self.get_filtered_creds(self.request)

        self.add_crack_rates_to_context(credential_per_cracked_account, ids_of_unqiue_accounts, context)

        context['hash_types'] = dict()
        for hash_type in filtered_creds.filter(hash_type__isnull=False).values("hash_type").distinct():
            context['hash_types'][HashCatMode(hash_type['hash_type']).name.replace("_", " ")] =\
                        filtered_creds.filter(hash_type=hash_type['hash_type']).count()

        context['password_is_username'] = filtered_creds.filter(account=F('secret')).count()

        self.add_reused_passwords_to_context(credential_per_cracked_account, context)
        self.add_common_prefixes_to_context(system, enabled, context)
        self.add_common_suffixes_to_context(system, enabled, context)

        # HaveIBeenPwned data
        records_still_to_process = filtered_creds.exclude(hash__isnull=True).exclude(hash="")\
            .filter(hash_type=HashCatMode.NTLM, haveibeenpwned_count__isnull=True)
        records_in_breaches = credential_per_cracked_account.filter(haveibeenpwned_count__gt=0)

        if not records_still_to_process.exists() and records_in_breaches.exists():
            context['top10pwned'] = records_in_breaches.values("secret","hash","haveibeenpwned_count").annotate(account_count=Count("hash")).order_by("-haveibeenpwned_count")[:10]

            if context['unique_user_accounts']:
                context['weak_unique_user_accounts'] = credential_per_cracked_account.exclude(
                    account__endswith='$').filter(haveibeenpwned_count__gt=0).count()
                context['weak_user_percent'] = context['weak_unique_user_accounts'] / context[
                    'unique_user_accounts'] * 100

            if context['unique_machine_accounts']:
                context['weak_unique_machine_accounts'] = credential_per_cracked_account.filter(
                    account__endswith='$').filter(haveibeenpwned_count__gt=0).count()
                context['weak_machine_percent'] = context['weak_unique_machine_accounts'] / context[
                    'unique_machine_accounts'] * 100

        # Figure out if we should render graphs based on bloodhound
        has_bloodhound_users = False
        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    has_bloodhound_users |= session.execute_read(self._has_bloodhound_users, system)
        context['has_bloodhound_users'] = has_bloodhound_users

        if has_bloodhound_users:
            context['old_passwords'] = self.get_accounts_with_oldest_passwords(enabled, system)

        # Cred reuse across systems

        if 'system' not in kwargs or not kwargs['system']:
            context['spanning_accounts'] = dict()  # Dict of account:bool to show if an account has been cracked (and to signify it is a spanning account by virtue of its presence)
            context['spanned_systems'] = dict()  # Dict of system:set(account) to show which systems the account spans
            for spanning_account in Credential.objects.raw("select * from event_tracker_credential as a, event_tracker_credential as b "
                                                           "where a.account=b.account and a.hash=b.hash and a.system is not null "
                                                           "and lower(trim(a.system, char(10) || char(13) || ' ')) not in ('', lower(trim(b.system, char(10) || char(13) || ' '))) "
                                                           "group by a.account, a.hash"):
                context['spanning_accounts'][spanning_account.account] = (spanning_account.secret != None)
                for system_spanned in Credential.objects.filter(account=spanning_account.account, hash=spanning_account.hash).values_list("system", flat=True).exclude(system__isnull=True).exclude(system="").distinct():
                    system_spanned = system_spanned.strip().lower()
                    if system_spanned not in context['spanned_systems']:
                        context['spanned_systems'][system_spanned] = set()
                    context['spanned_systems'][system_spanned].add(spanning_account.account)

            context['spanning_accounts_cracked_count'] = sum(context['spanning_accounts'].values())

        # Query for finding accounts with a prefix that share the same creds as the non-prefixed account:
        # SELECT a.system, a.account, b.account
        #   FROM event_tracker_credential as a,  event_tracker_credential as b
        #   WHERE a.account like '%' || b.account and a.hash=b.hash and a.account != b.account and a.system = b.system
        #   GROUP BY b.account order by a.account;

        return context

    @staticmethod
    def get_accounts_with_oldest_passwords(enabled, system):
        # Old passwords
        old_passwords = []
        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    with contextlib.suppress(ClientError):  # Likely caused by no accounts being enabled for this system
                        old_passwords = session.execute_read(CredentialStatsView._oldest_password_ages, system,
                                                             enabled)
                        # TODO merge multiple old_passwords from different servers, rather than overwriting
        return old_passwords

    @staticmethod
    def add_reused_passwords_to_context(credential_per_account, context):
        context['top10'] = credential_per_account.values("secret").annotate(occurrences=Count("secret"))\
            .filter(occurrences__gte=2).order_by("-occurrences")[:10]

    @staticmethod
    def add_common_prefixes_to_context(system, enabled, context):
        if not system:
            duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''" +
                           (" and enabled='1'" if enabled else ""))
        else:
            system = system.replace("'", "")
            duckdb.execute(f"CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != '' and system COLLATE NOCASE = '{system}'" +
                           (" and enabled='1'" if enabled else ""))

        # Extract the rtrimed words
        duckdb.execute(
            "select rtrim(secret, $1) as t, count(*) as c from distinct_secrets where t != secret and t != '' group by t having c > 1 order by c desc limit 10",
            [SYMBOLS + DIGITS])

        context['top10prefixstrings'] = duckdb.fetchmany(10)

    @staticmethod
    def add_common_suffixes_to_context(system, enabled, context):
        if not system:
            duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''" +
                           (" and enabled='1'" if enabled else ""))
        else:
            system = system.replace("'", "")
            duckdb.execute(f"CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != '' and system COLLATE NOCASE = '{system}'" +
                           (" and enabled='1'" if enabled else ""))

        # Extract the ltrimed words
        duckdb.execute(
            "select ltrim(secret, $1) as t, count(*) as c from distinct_secrets where t != secret and t != '' group by t having c > 1 order by c desc limit 10",
            [SYMBOLS + DIGITS])

        context['top10suffixstrings'] = duckdb.fetchmany(10)

    @staticmethod
    def add_crack_rates_to_context(credential_per_account, ids_of_unqiue_accounts, context):
        context['unique_user_accounts'] = ids_of_unqiue_accounts.exclude(account__endswith='$').count()
        if context['unique_user_accounts']:
            context['cracked_unique_user_accounts'] = credential_per_account.exclude(account__endswith='$').count()
            context['cracked_user_percent'] = context['cracked_unique_user_accounts'] / context[
                'unique_user_accounts'] * 100
        context['unique_machine_accounts'] = ids_of_unqiue_accounts.filter(account__endswith='$').count()
        if context['unique_machine_accounts']:
            context['cracked_unique_machine_accounts'] = credential_per_account.filter(account__endswith='$').count()
            context['cracked_machine_percent'] = context['cracked_unique_machine_accounts'] / context[
                'unique_machine_accounts'] * 100

    @staticmethod
    def get_filtered_creds(request):
        start = time.time()

        statsfilter = request.session.get('credentialstatsfilter', {})
        system = statsfilter.get("system", None) or None
        enabled = statsfilter.get("enabled", False)
        plot_uncracked = statsfilter.get("plot_uncracked", False)

        if system:
            filtered_creds = Credential.objects.filter(system=system)
        else:
            filtered_creds = Credential.objects

        if enabled:
            filtered_creds = filtered_creds.filter(enabled=1)

        # Used to count the number of distinct accounts
        ids_of_unqiue_accounts = filtered_creds.values("system", "account").annotate(x=Count(1)).annotate(
            max_id=Max("id")).all()

        # Just the cracked accounts
        ids_of_unqiue_cracked_accounts = filtered_creds.filter(secret__isnull=False).values("system", "account").annotate(x=Count(1)).annotate(
            max_id=Max("id")).all()
        credential_per_cracked_account = filtered_creds.filter(secret__isnull=False).filter(
            id__in=Subquery(ids_of_unqiue_cracked_accounts.values("max_id")))

        # Accounts which have no cracked credentials. Accounts which occur multiple times with even 1 cracked cred will appear in the previous dataset only to avoid inflating total user counts
        ids_of_unqiue_uncracked_accounts = filtered_creds.values("system", "account").annotate(x=Count(1)) \
             .annotate(cracked=Count("pk", filter=Q(secret__isnull=False))) \
             .annotate(not_cracked=Count("pk", filter=Q(secret__isnull=True))).filter(cracked=0, not_cracked__gt=0) \
             .annotate(max_id=Max("id"))

        credential_per_uncracked_account = filtered_creds.filter(secret__isnull=True).filter(
            id__in=Subquery(ids_of_unqiue_uncracked_accounts.values("max_id")))

        print(f"Populated creds in {time.time() - start}")

        return credential_per_cracked_account, credential_per_uncracked_account, filtered_creds, ids_of_unqiue_accounts, system, enabled, plot_uncracked


def password_complexity_piechart(request, task_id):
    credential_per_cracked_account, credential_per_uncracked_account, _, _, system, enabled, plot_uncracked = CredentialStatsView.get_filtered_creds(request)

    fig = plot_password_complexity_piechart(credential_per_cracked_account, credential_per_uncracked_account, system,
                                            enabled, plot_uncracked)
    response = HttpResponse(content_type='image/png')
    fig.savefig(response, format='png')

    return response

def plot_password_complexity_piechart(credential_per_cracked_account, credential_per_uncracked_account, system, enabled,
                                      plot_uncracked):
    credential_per_cracked_account.update(complexity=Case(
        When(secret="", then=Value("blank")),
        When(secret__regex=r"^\d+$", then=Value("numeric")),
        When(secret__regex=r'^[ ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦|]+$', then=Value("special")),
        When(secret__regex=r'^[a-z]+$', then=Value("loweralpha")),
        When(secret__regex=r'^[A-Z]+$', then=Value("upperalpha")),
        When(secret__regex=r'^[a-zA-Z]+$', then=Value("mixedalpha")),
        When(secret__regex=r'^[a-z0-9]+$', then=Value("loweralphanum")),
        When(secret__regex=r'^[A-Z0-9]+$', then=Value("upperalphanum")),
        When(secret__regex=r'^[a-zA-Z0-9]+$', then=Value("mixedalphanum")),
        When(secret__regex=r'^[a-z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦|]+$', then=Value("loweralphaspecial")),
        When(secret__regex=r'^[A-Z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦|]+$', then=Value("upperalphaspecial")),
        When(secret__regex=r'^[A-Za-z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦|]+$',
             then=Value("mixedalphaspecial")),
        When(secret__regex=r'^[a-z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦0-9|]+$',
             then=Value("loweralphaspecialnum")),
        When(secret__regex=r'^[A-Z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦0-9|]+$',
             then=Value("upperalphaspecialnum")),
        When(secret__regex=r'^[A-Za-z ¬`!"£$%^&*()\-=_+{}\[\];\'#:@~,./\\<>?€¦0-9|]+$',
             then=Value("mixedalphaspecialnum")),
        default=Value("unknown")
    ))

    counts = {}

    counts.update(credential_per_cracked_account.aggregate(
        blank=Count("pk", filter=Q(complexity="blank")),
        numeric=Count("pk", filter=Q(complexity="numeric")),
        special=Count("pk", filter=Q(complexity="special")),
        loweralpha=Count("pk", filter=Q(complexity="loweralpha")),
        upperalpha=Count("pk", filter=Q(complexity="upperalpha")),
        mixedalpha=Count("pk", filter=Q(complexity="mixedalpha")),
        loweralphanum=Count("pk", filter=Q(complexity="loweralphanum")),
        upperalphanum=Count("pk", filter=Q(complexity="upperalphanum")),
        mixedalphanum=Count("pk", filter=Q(complexity="mixedalphanum")),
        loweralphaspecial=Count("pk", filter=Q(complexity="loweralphaspecial")),
        upperalphaspecial=Count("pk", filter=Q(complexity="upperalphaspecial")),
        mixedalphaspecial=Count("pk", filter=Q(complexity="mixedalphaspecial")),
        loweralphaspecialnum=Count("pk", filter=Q(complexity="loweralphaspecialnum")),
        upperalphaspecialnum=Count("pk", filter=Q(complexity="upperalphaspecialnum")),
        mixedalphaspecialnum=Count("pk", filter=Q(complexity="mixedalphaspecialnum")),
    ))
    fig = Figure(figsize=(10, 8))
    ax = fig.subplots(2, height_ratios=[3, 1])
    piesegments = [counts['blank'], counts['numeric'], counts['special'],
                   counts['loweralpha'], counts['upperalpha'], counts['mixedalpha'],
                   counts['loweralphanum'], counts['upperalphanum'], counts['mixedalphanum'],
                   counts['loweralphaspecial'], counts['upperalphaspecial'], counts['mixedalphaspecial'],
                   counts['loweralphaspecialnum'], counts['upperalphaspecialnum'],
                   counts['mixedalphaspecialnum']]
    pielabels = ["Blank", "Numeric only", "Symbols only",
                 "Lowercase only", "Uppercase only", "Mixedcase",
                 "Lowercase & Number(s)", "Uppercase & Number(s)", "Mixedcase & Number(s)",
                 "Lowercase & Symbol(s)", "Uppercase & Symbol(s)", "Mixedcase & Symbol(s)",
                 "Lowercase, Symbol(s) & Number(s)", "Uppercase, Symbol(s) & Number(s)",
                 "Mixedcase, Symbol(s) & Number(s)"]

    if plot_uncracked:
        piesegments.append(credential_per_uncracked_account.count())
        pielabels.append("Unknown")

    # Turn the plain old lists into numpy versions if required, and throw away any values with 0 accounts using compress()
    piesegments2 = np.array(list(itertools.compress(piesegments, piesegments)))
    pielabels2 = list(itertools.compress(pielabels, piesegments))
    rescale = lambda y: y if len(y) == 1 else (y - np.min(y)) / (np.max(y) - np.min(y))

    if plot_uncracked:
        # Pick colors from the colormap for n-1 segments and append a new color for the "unknown"
        colors = badness_colormap(rescale(range(len(piesegments2) - 1)))
        colors = np.append(colors, to_rgba_array(UNKNOWN_COLOR), 0)
    else:
        # Pick colors from the colormap for all segments
        colors = badness_colormap(rescale(range(len(piesegments2))))

    wedges, texts = ax[0].pie(piesegments2, colors=colors)
    ax[0].set_title(
        f"Password Complexity of {'Cracked ' if not plot_uncracked else ''}Passwords for{chr(10)}All {'Enabled ' if enabled else ''}Accounts{f' on {system}' if system else ''}")
    percents = piesegments2 * 100 / piesegments2.sum()
    ax[1].axis('off')  # Hide the dummy 2nd plot
    ax[1].legend(wedges, [f'{l}: {y:,} account{"s" if y != 1 else ""} ({s:.2f}%)' for l, y, s in
                          zip(pielabels2, piesegments2, percents)],
                 title="Key",
                 loc="upper center",
                 ncol=2)

    return fig


def password_structure_piechart(request, task_id):
    credential_per_cracked_account, credential_per_uncracked_account, _, _, system, enabled, plot_uncracked = CredentialStatsView.get_filtered_creds(request)

    fig = plot_password_structure_piechart(credential_per_cracked_account, credential_per_uncracked_account, system,
                                           enabled, plot_uncracked)
    response = HttpResponse(content_type='image/png')
    fig.savefig(response, format='png')

    return response

def plot_password_structure_piechart(credential_per_cracked_account, credential_per_uncracked_account, system, enabled,
                                     plot_uncracked):
    calculate_char_masks(credential_per_cracked_account)

    structurecounts = credential_per_cracked_account.values("structure").annotate(count=Count("structure")).order_by("count")

    fig = Figure(figsize=(10, 8))
    ax = fig.subplots(2, height_ratios=[3, 1])
    piesegments = list(structurecounts.values_list("count", flat=True))
    pielabels = list(structurecounts.values_list("structure", flat=True))

    if plot_uncracked:
        piesegments.append(credential_per_uncracked_account.count())
        pielabels.append("Unknown")

    # Turn the plain old lists into numpy versions if required, and throw away any values with 0 accounts using compress()
    piesegments2 = np.array(list(itertools.compress(piesegments, piesegments)))
    pielabels2 = list(itertools.compress(pielabels, piesegments))
    rescale = lambda y: y if len(y) == 1 else (y - np.min(y)) / (np.max(y) - np.min(y))

    if plot_uncracked:
        # Pick colors from the colormap for n-1 segments and append a new color for the "unknown"
        colors = intensity_colormap(rescale(range(len(piesegments2) - 1)))
        colors = np.append(colors, to_rgba_array(UNKNOWN_COLOR), 0)
    else:
        # Pick colors from the colormap for all segments
        colors = intensity_colormap(rescale(range(len(piesegments2))))

    wedges, texts = ax[0].pie(piesegments2, colors=colors)
    ax[0].set_title(
        f"Structure of {'Cracked ' if not plot_uncracked else ''}Passwords for{chr(10)}All {'Enabled ' if enabled else ''}Accounts{f' on {system}' if system else ''}")
    percents = piesegments2 * 100 / piesegments2.sum()
    ax[1].axis('off')  # Hide the dummy 2nd plot
    ax[1].legend(wedges, [f'{l}: {y:,} account{"s" if y != 1 else ""} ({s:.2f}%)' for l, y, s in
                          zip(pielabels2, piesegments2, percents)],
                 title="Key",
                 loc="upper center",
                 ncol=2)

    return fig


def password_length_chart(request, task_id):
    credential_per_cracked_account, credential_per_uncracked_account, _, _, system, enabled, plot_uncracked = CredentialStatsView.get_filtered_creds(request)

    fig = plot_password_length_chart(credential_per_cracked_account, credential_per_uncracked_account, system, enabled,
                                     plot_uncracked)
    response = HttpResponse(content_type='image/png')
    fig.savefig(response, format='png')

    return response

def plot_password_length_chart(credential_per_cracked_account, credential_per_uncracked_account, system, enabled,
                               plot_uncracked):
    fig = Figure(figsize=(7, 8))
    ax = fig.subplots(2)

    lengths = credential_per_cracked_account.annotate(length=Length("secret")).order_by("length").values("length").annotate(
        occurrences=Count("length"))

    x = np.array(lengths.values_list("length", flat=True))
    y = np.array(lengths.values_list("occurrences", flat=True))
    rescale = lambda y: y if len(y) == 1 else (y - np.min(y)) / (np.max(y) - np.min(y))

    if plot_uncracked:
        x = np.append(-1, x)
        y = np.append(credential_per_uncracked_account.count(), y)

        # Prepend a new color for the "unknown" and pick colors from the colormap for n-1 segments
        colors = badness_colormap(rescale(range(len(x) - 1)))
        colors = np.insert(colors, 0, to_rgba_array(UNKNOWN_COLOR), 0)
    else:
        # Pick colors from the colormap for all segments
        colors = badness_colormap(rescale(range(len(x))))

    bars = ax[0].bar(x, y,
                     color=colors,
                     label=x)
    ax[0].set_ylabel('Number of accounts')
    ax[0].set_xlabel(f"Length of {'cracked ' if not plot_uncracked else ''}password")

    ax[0].set_title(
        f"Length of {'Cracked ' if not plot_uncracked else ''}Passwords for{chr(10)}All {'Enabled ' if enabled else ''}Accounts{f' on {system}' if system else ''}")

    if len(x) < 5:
        x_nbins = len(x) + 1
    else:
        x_nbins = "auto"
    ax[0].xaxis.set_major_locator(MaxNLocator(steps=[1, 2, 5, 10], nbins=x_nbins))

    if np.max(y) < 5:
        y_nbins = np.max(y) + 1
    else:
        y_nbins = "auto"
    ax[0].yaxis.set_major_locator(MaxNLocator(steps=[1, 2, 5, 10], nbins=y_nbins))
    
    ax[1].axis('off')  # Hide the dummy 2nd plot
    percents = y * 100 / y.sum()
    ax[1].legend(bars, [(f'{l} character{"s" if l != 1 else ""}' if l >= 0 else 'Unknown')
                            + f': {y:,} account{"s" if y != 1 else ""} ({s:.2f}%)' for
                        l, y, s in zip(x, y, percents)],
                 loc="upper center",
                 ncol=2)

    return fig


def password_age_chart(request, task_id):
    statsfilter = request.session.get('credentialstatsfilter', {})
    system = statsfilter.get("system", None) or None
    enabled = statsfilter.get("enabled", False)

    fig = plot_password_age_chart(enabled, system)
    if fig:
        response = HttpResponse(content_type='image/png')
        fig.savefig(response, format='png')

        return response
    else:
        return HttpResponseNotFound()

def plot_password_age_chart(enabled, system):
    # Password age
    password_ages = []
    for server in BloodhoundServer.objects.filter(active=True).all():
        if driver := get_driver_for(server):
            with driver.session() as session:
                with contextlib.suppress(ClientError):  # Likely caused by no accounts being enabled for this system
                    password_ages = session.execute_read(CredentialStatsView._bucket_password_ages, system, enabled)
                    #TODO merge multiple password_ages from different servers, rather than overwriting
    if password_ages:
        fig = Figure(figsize=(8, 7))
        ax = fig.subplots(2)

        data = np.array(password_ages)

        x = data[:,0]  # First column of the numpy 2-D array
        y = data[:,1]  # Second column of the numpy 2-D array

        rescale = lambda y: y if len(y) == 1 else (y - np.min(y)) / (np.max(y) - np.min(y))
        bars = ax[0].bar(x, y,
                         color=badness_colormap.reversed()(rescale(x)),
                         label=x)

        ax[0].set_ylabel('Number of accounts')
        ax[0].set_xlabel('Years since password change')
        ax[0].xaxis.set_major_locator(MaxNLocator(steps=[1, 2, 5, 10]))
        ax[0].set_title(
            f"Password Age for{chr(10)}All {'Enabled ' if enabled else ''}Accounts{f' on {system}' if system else ''}")

        ax[1].axis('off')  # Hide the dummy 2nd plot
        percents = y * 100 / y.sum()
        ax[1].legend(bars, [f'{l} to {l + 1} years: {y:,} account{"s" if y != 1 else ""} ({s:.2f}%)' for l, y, s in
                            zip(x, y, percents)],
                     loc="upper center",
                     ncol=2)

        return fig
    else:
        return None

class CredentialListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_credential'
    model = Credential
    template_name = 'event_tracker/credential_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['hashtypes'] = list()

        modes = Credential.objects.filter(secret__isnull=True, hash_type__isnull=False)\
            .values_list("hash_type", flat=True).distinct()

        for mode in modes:
            context['hashtypes'].append(HashCatMode(mode))

        if CredentialReportingPluginPoint.get_plugins_qs().filter(status=ENABLED).exists():
            context['plugins'] = []
            for plugin in CredentialReportingPluginPoint.get_plugins():
                if plugin.is_access_permitted(self.request.user):
                    context['plugins'].append(plugin)

        return context


class CredentialListJson(PermissionRequiredMixin, BaseDatatableView):
    permission_required = 'event_tracker.view_credential'
    # The model we're going to show
    model = Credential

    # define the columns that will be returned
    columns = ['system', 'account', 'enabled', 'secret', 'purpose', '']

    # define column names that will be used in sorting
    # order is important and should be same as order of columns
    # displayed by datatables. For non-sortable columns use empty
    # value like ''
    order_columns = ['system', 'account', 'enabled', 'secret', 'purpose', '']

    # set max limit of records returned, this is used to protect our site if someone tries to attack our site
    # and make it return huge amount of data
    max_display_length = 500

    def render_column(self, row, column):
        if column == 'system':
            if not row.system:
                return "<span class='system'>-</span>"
            else:
                return "<span class='system'>" + truncatechars_html(breakonpunctuation(escape(row.system)), 125) + "</span>"
        elif column == 'account':
            return '<a title="Copy to clipboard" class="copyToClipboard"><span class="account">' + escape(row.account) + '</span><i class="fa-regular fa-paste ms-1"></i></a>'
        elif column == 'secret':
            if row.secret == None:
                return f"<em class='text-muted'>{hash_type_name(row.hash_type).replace('_', ' ')} not cracked</em>"
            elif row.secret == "":
                return f"<em class='text-muted'>Empty</em>"
            else:
                return '<a title="Copy to clipboard" class="copyToClipboard"">' + escape(row.secret) + '<i class="fa-regular fa-paste ms-1"></i></a>'
        elif column == 'enabled':
            if row.enabled:
                return '<i class="fa-solid fa-check"></i>'
            else:
                return '<i class="fa-solid fa-xmark"></i>'
        elif column == 'purpose' and not row.purpose:
            return "-"
        elif column == '':  # The column with button in
            return f"""<a href="{reverse('event_tracker:credential-update', kwargs={'task_id': 1,'pk': row.id})}" role="button" class="btn btn-primary btn-sm" data-toggle="tooltip" title="Edit Credential"><i class="fa-regular fa-pen-to-square"></i></a>
                       <a role="button" class="btn btn-danger btn-sm" data-toggle="tooltip" title="Delete Credential" data-delete-url="{reverse('event_tracker:credential-delete', kwargs={'task_id': 1,'pk': row.id})}"><i class="fa-regular fa-trash-can"></i></a>"""
        else:
            return super(CredentialListJson, self).render_column(row, column)


    def filter_queryset(self, qs):
        # use parameters passed in GET request to filter queryset

        # simple example:
        search = self.request.GET.get('search[value]', None)
        if search:
            terms = search.split(" ")

            for term in terms:
                q = Q(account__icontains=term) | Q(secret__icontains=term) | Q(system__icontains=term) | Q(purpose__icontains=term) | Q(hash=term)
                qs = qs.filter(q)

        return qs


class CredentialForm(forms.ModelForm):
    class Meta:
        model = Credential
        fields = "source_time", "system", "account", "enabled", "secret", "hash", "hash_type", "purpose", "source"

    source_time = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), required=False)


class CredentialCreateView(PermissionRequiredMixin, CreateView):
    permission_required = 'event_tracker.add_credential'
    model = Credential
    form_class = CredentialForm

    def get_success_url(self):
        return reverse_lazy('event_tracker:credential-list', kwargs={"task_id": 1})

    def get_context_data(self, **kwargs):
        context = super(CredentialCreateView, self).get_context_data(**kwargs)
        context['action'] = "Create"
        return context

    def get_initial(self):
        return {
            "source_time": timezone.localtime().strftime("%Y-%m-%dT%H:%M"),
        }


class CredentialUpdateView(PermissionRequiredMixin, UpdateView):
    permission_required = 'event_tracker.change_credential'
    model = Credential
    form_class = CredentialForm

    def get_success_url(self):
        return reverse_lazy('event_tracker:credential-list', kwargs={"task_id": 1})

    def get_context_data(self, **kwargs):
        context = super(CredentialUpdateView, self).get_context_data(**kwargs)
        context['action'] = "Update"
        return context

    def get_initial(self):
        initial = {}
        if self.object.source_time is not None:
            initial["source_time"] = timezone.localtime(self.object.source_time).strftime("%Y-%m-%dT%H:%M")
        return initial


class CredentialDeleteView(PermissionRequiredMixin, DeleteView):
    permission_required = 'event_tracker.delete_credential'
    model = Credential

    def get_success_url(self):
        return reverse_lazy('event_tracker:credential-list', kwargs={"task_id": 1})


@permission_required('event_tracker.view_credential')
def credential_masklist(request, task_id, min_len):
    calculate_char_masks(Credential.objects.all())

    # The char_masks of found secrets, ordered by the minimal effort boosted by most commonly occurring
    optimised_masks = Credential.objects.exclude(char_mask="").exclude(char_mask__isnull=True).values("char_mask", "char_mask_effort").annotate(
        freq=Cast(Count("char_mask"), FloatField())).annotate(
        prob=ExpressionWrapper(F('char_mask_effort') / F('freq'), output_field=FloatField())).annotate(
        len_tot=Length("char_mask")).annotate(len=F('len_tot') / 2).filter(len__gte = min_len).order_by("prob")

    return HttpResponse(content="\n".join(optimised_masks.values_list("char_mask", flat=True)),
                        headers={'Content-Disposition':
                                     f'attachment; filename="masklist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.hcmask"'})


@permission_required('event_tracker.view_credential')
def prefix_masklist(request, task_id):
    # Extract the prefix masks
    duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''")
    results = duckdb.execute("select premask, searchspace, count(*) as c, searchspace / count(*) as hitrate from (select secret, ltrim(secret, $1) as t, "
                          "secret[:-length(t) - 1] as pre, "
                          "regexp_replace(regexp_replace(pre, $2, '?s', 'g'), $3, '?d', 'g') as premask, "
                          "len(string_split(premask, '?d')) - 1 as digs, "
                          "len(string_split(premask, '?s')) - 1 as symbs, "
                          "(10 ** digs) * (34 ** symbs) as searchspace "
                          "from distinct_secrets) where pre != '' group by premask, searchspace order by hitrate", [SYMBOLS + DIGITS, SYMBOL_REGEX, DIGIT_REGEX])

    return HttpResponse(content="\n".join([row[0] for row in results.fetchall()]),
                        headers={'Content-Disposition':
                                     f'attachment; filename="prefix-masklist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.hcmask"'})


@permission_required('event_tracker.view_credential')
def suffix_masklist(request, task_id):
    # Extract the suffix masks
    duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''")
    results = duckdb.execute("select sufmask, searchspace, count(*) as c, searchspace / count(*) as hitrate from (select secret, rtrim(secret, $1) as t, "
                          "secret[length(t) + 1:] as suf, "
                          "regexp_replace(regexp_replace(suf, $2, '?s', 'g'), $3, '?d', 'g') as sufmask, "
                          "len(string_split(sufmask, '?d')) - 1 as digs, "
                          "len(string_split(sufmask, '?s')) - 1 as symbs, "
                          "(10 ** digs) * (34 ** symbs) as searchspace "
                          "from distinct_secrets) where suf != '' group by sufmask, searchspace order by hitrate", [SYMBOLS + DIGITS, SYMBOL_REGEX, DIGIT_REGEX])

    return HttpResponse(content="\n".join([row[0] for row in results.fetchall()]),
                        headers={'Content-Disposition':
                                     f'attachment; filename="suffix-masklist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.hcmask"'})


def calculate_char_masks(credential_queryset):
    """
    Algorithms based on https://github.com/crypt0rr/pack/
    """
    secrets = credential_queryset.filter(secret__isnull=False, char_mask__isnull=True).values_list("secret",
                                                                                                  flat=True).distinct()
    for secret in secrets:
        char_mask = ""
        char_mask_effort = 1
        structure = list()

        try:
            for char in secret:
                ordinal = ord(char)
                if 48 <= ordinal <= 57:  # digit
                    char_mask += "?d"
                    char_mask_effort *= 10
                    if not (structure and structure[-1] == "Number(s)"):
                        structure.append("Number(s)")
                elif 65 <= ordinal <= 90:  # uppercase
                    char_mask += "?u"
                    char_mask_effort *= 26
                    if not (structure and structure[-1] == "Letter(s)"):
                        structure.append("Letter(s)")
                elif 97 <= ordinal <= 122:  # lowercase
                    char_mask += "?l"
                    char_mask_effort *= 26
                    if not (structure and structure[-1] == "Letter(s)"):
                        structure.append("Letter(s)")
                else:  # symbol
                    char_mask += "?s"
                    char_mask_effort *= 33
                    if not (structure and structure[-1] == "Symbol(s)"):
                        structure.append("Symbol(s)")

            if len(structure) > 3:
                structure = "Other"
            elif len(structure) == 0:
                structure = "None"
            else:
                structure = "..".join(structure)

            # Accuracy isn't too important, so 6 least significant digits from effort, and cap at max DB value
            char_mask_effort = min(char_mask_effort // 1_000_000, Credential.char_mask_effort.field.MAX_BIGINT)

            Credential.objects.filter(secret=secret).update(char_mask=char_mask, char_mask_effort=char_mask_effort,
                                                            structure=structure)
        except UnicodeError:
            pass


def _get_description_words(tx):
    query = "MATCH (n:Base) where n.description is not null return n.description as words " \
            "union MATCH (n:Base) where n.title is not null return n.title as words"
    return list(tx.run(query))


def _get_dn_words(tx):
    query = "MATCH (n:Base) where n.distinguishedname is not null return n.distinguishedname as words"
    return list(tx.run(query))


@permission_required('event_tracker.view_credential')
def credential_wordlist(request, task_id):
    description_words = set()

    description_words.update(Credential.objects.filter(secret__isnull=False).values_list("secret", flat=True).distinct())
    description_words.update(Credential.objects.filter(account__isnull=False).values_list("account", flat=True).distinct())
    description_words.update(Credential.objects.filter(system__isnull=False).values_list("system", flat=True).distinct())

    special_char_seperated = re.compile(r'[a-zA-Z0-9]{3,}')
    camel_case_subwords = re.compile(r'[A-Z][a-z]+')
    whitespace_seperated = re.compile(r'\S{3,}')
    dn_values = re.compile(r'[^,=]{3,}(?!=)')

    extra_description_words = set()
    for description_word in description_words:
        extra_description_words.update(re.findall(special_char_seperated, description_word))
        extra_description_words.update(re.findall(camel_case_subwords, description_word))
    description_words.update(extra_description_words)

    for server in BloodhoundServer.objects.filter(active=True).all():
        if driver := get_driver_for(server):
            with driver.session() as session:
                with contextlib.suppress(ClientError):  # Likely caused by no accounts being enabled for this system
                    for description in session.execute_read(_get_description_words):
                        description_words.update(re.findall(special_char_seperated, description[0]))
                        description_words.update(re.findall(camel_case_subwords, description[0]))
                        description_words.update(re.findall(whitespace_seperated, description[0]))
                    for dn in session.execute_read(_get_dn_words):
                        description_words.update(re.findall(dn_values, dn[0]))

    words_only = re.compile(r'[a-zA-Z]{4,}')
    for word in description_words.copy():
        inner_words = re.findall(words_only, word)
        description_words.update(inner_words)

    return HttpResponse(content="\n".join(description_words),
                        headers={'Content-Disposition':
                                     f'attachment; filename="wordlist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt"'})


@permission_required('event_tracker.view_credential')
def prefix_wordlist(request, task_id):
    # Extract the rtrimed words
    duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''")
    results = duckdb.execute("select rtrim(secret, $1) as t, count(*) as c from distinct_secrets where t != secret  and t != '' group by t order by c desc", [SYMBOLS + DIGITS])

    return HttpResponse(content="\n".join([row[0] for row in results.fetchall()]),
                        headers={'Content-Disposition':
                                     f'attachment; filename="prefix-wordlist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt"'})


@permission_required('event_tracker.view_credential')
def suffix_wordlist(request, task_id):
    # Extract the ltrimed words
    duckdb.execute("CREATE OR REPLACE TEMP VIEW distinct_secrets AS SELECT distinct secret FROM event_tracker_credential where secret is not null and secret != ''")
    results = duckdb.execute("select ltrim(secret, $1) as t, count(*) as c from distinct_secrets where t != secret and t != '' group by t order by c desc", [SYMBOLS + DIGITS])

    return HttpResponse(content="\n".join([row[0] for row in results.fetchall()]),
                        headers={'Content-Disposition':
                                     f'attachment; filename="suffix-wordlist-{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt"'})


@permission_required('event_tracker.view_credential')
def credential_uncracked_hashes(request, task_id, hash_type):
    values = Credential.objects.filter(secret__isnull=True, hash_type=hash_type).values_list("hash", flat=True).distinct()

    return HttpResponse(content="\n".join(values),
                        headers={'Content-Disposition':
                                     f'attachment; filename="hashes-{hash_type}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt"'})


def pwdump_iterator():
    # Gets the newest lm hash and nt hash for each user that has at least one lm hash or nt hash
    values = Credential.objects.filter(Q(hash_type=1000) | Q(hash_type=3000)).annotate(lmhash=Subquery(
        Credential.objects.filter(hash_type=3000, system=OuterRef("system"), account=OuterRef("account")).order_by(
            "-id").values("hash"))).annotate(nthash=Subquery(
        Credential.objects.filter(hash_type=1000, system=OuterRef("system"), account=OuterRef("account")).order_by(
            "-id").values("hash"))).values("system", "account", "lmhash", "nthash").distinct()

    # Yield a line in pwdump format
    for line in values:
        if line["system"]:
            yield f"{line['system']}\\{line['account']}::{line['lmhash'] or EMPTY_LMHASH}:{line['nthash'] or EMPTY_NTLMHASH}:::\n"
        else:
            yield f"{line['account']}::{line['lmhash'] or EMPTY_LMHASH}:{line['nthash'] or EMPTY_NTLMHASH}:::\n"


@permission_required('event_tracker.view_credential')
def credential_uncracked_hashes_pwdump(request, task_id):
    return StreamingHttpResponse(pwdump_iterator(),
                        headers={'Content-Disposition':
                                     f'attachment; filename="hashes-pwdump-{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt"'})


class CrackedHashesForm(forms.Form):
    file = forms.FileField(help_text="The output of `hashcat --show [hash_file]`, or a hashcat.potfile...", required=False)
    text = forms.CharField(widget=Textarea(attrs={"style": "font-family: monospace;", "spellcheck": "false"}), help_text="...and/or paste hash:cleartext or user:hash:cleartext here (assumes DOS (CP437) encoding)", required=False)


# How hashcat copes with non-ascii content, or content with :'s in
hashcat_hex_re = re.compile(r"\$HEX\[([0-9a-f]{2,})]")


class UploadCrackedHashes(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.change_credential'
    template_name = "event_tracker/credential_cracked_upload.html"

    def get_context_data(self, **kwargs):
        context = super(TemplateView, self).get_context_data(**kwargs)
        context['form'] = CrackedHashesForm()
        return context

    def post(self, request, *args, **kwargs):
        form = CrackedHashesForm(request.POST, request.FILES)
        if form.is_valid():
            total_accounts = 0
            total_hashes = 0

            previous_chunk = ""

            # Handle the file upload
            if "file" in request.FILES:
                for chunk in request.FILES['file'].chunks():
                    chunk_txt = chunk.decode("UTF-8")
                    last_newline = chunk_txt.rfind("\n")

                    chunk_main = previous_chunk + chunk_txt[:last_newline]

                    new_accounts, new_hashes = self.add_credentials(chunk_main)
                    total_accounts += new_accounts
                    total_hashes += new_hashes

                    previous_chunk = chunk_txt[last_newline:]

                # Handle final part of upload between last newline and EOF
                if previous_chunk.strip():
                    new_accounts, new_hashes = self.add_credentials(previous_chunk)
                    total_accounts += new_accounts
                    total_hashes += new_hashes

            # Handle the text field
            if form.cleaned_data["text"]:
                new_accounts, new_hashes = self.add_credentials(form.cleaned_data["text"].encode("cp437").decode("utf-8"))
                total_accounts += new_accounts
                total_hashes += new_hashes

            return redirect(reverse_lazy('event_tracker:credential-cracked-hashes-upload-done',
                                         kwargs={'task_id': kwargs['task_id'],
                                                 'cracked_hashes': total_hashes,
                                                 'cracked_accounts': total_accounts}))


    def add_credentials(self, input):
        start = time.time()
        total_accounts = 0
        total_hashes = 0

        # Unique Lines Only
        lines = set(input.splitlines())

        for line in lines:
            accounts_changed = UploadCrackedHashes.update_hash_with_plaintext(line)
            total_accounts += accounts_changed
            total_hashes += 1 if accounts_changed else 0

        print(f"Imported cracked hashes in {time.time() - start:.2f} seconds")

        return total_accounts, total_hashes


    @staticmethod
    def update_hash_with_plaintext(line):
        unknown_creds = Credential.objects.filter(secret__isnull=True)

        try:
            hash, plain_text = line.rsplit(":", 1)
            # Cope with a pair of colons as separators, as per hashtopolis dealing with unsalted hashes
            hash = hash.rstrip(":")

            if ":" in hash:  # Hash part contains a colon in the middle, might be prefixed with usernames
                user_part, hash_part = hash.split(":", 1)
                creds_matching_hash = unknown_creds.filter(Q(hash__iexact=hash) | Q(account__iexact=user_part, hash__iexact=hash_part))
            else:
                creds_matching_hash = unknown_creds.filter(hash__iexact=hash)

            if creds_matching_hash.exists():
                for hex_match in re.finditer(hashcat_hex_re, plain_text):
                    hex_match_start, hex_match_end = hex_match.span()
                    plain_text = plain_text[:hex_match_start] \
                                     + bytes.fromhex(hex_match.group(1)).decode('ISO-8859-1') \
                                     + plain_text[hex_match_end:]


                return creds_matching_hash.update(secret=plain_text)
        except Exception as e:
            print(f"[!] Skipping line: {line} - Exception: {e}")

        return 0


class UploadCrackedHashesDone(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.change_credential'
    template_name = "event_tracker/credential_cracked_upload_done.html"


class UploadDumpDone(PermissionRequiredMixin, TemplateView):
    permission_required = 'event_tracker.change_credential'
    template_name = "event_tracker/credential_dump_upload_done.html"


class HashesForm(forms.Form):
    TYPE_CHOICES = [('grep', 'Text file, e.g. tool output (Hashes extracted via regex)'),
                    ('keepass', 'Keepass v1 .csv export'),
                    ('user:hash', 'User:Hash'),
                    ('user:secret', 'User:Secret'),
                    ('user:hash:secret', 'User:Hash:Secret'),
                    ('pwdump', "PWDump - e.g. corp.local\\bob:1021:aad3b435b51404eeaad3b435b51404ee:8027ce065399052165fa94b713980e33:::")]

    file = forms.FileField()
    type = forms.ChoiceField(choices=TYPE_CHOICES, widget=forms.RadioSelect())
    system = forms.CharField(required=False, help_text="The scope of the accounts, i.e. the name of the domain or host they apply to")
    hash_type = forms.ChoiceField(help_text="The hashcat module number for the hash", choices=[(tag.value, f"{tag.name} ({tag.value})") for tag in HashCatMode], required=False)


class UploadHashes(PermissionRequiredMixin, FormView):
    permission_required = 'event_tracker.add_credential'
    template_name = "event_tracker/credential_hashes_upload.html"
    form_class = HashesForm


    def form_valid(self, form):
        # There's a risk that a hash spans two chunks and therefore won't get captured by regex, so split on
        # newlines
        previous_chunk = ""
        total_saved_hashes = 0
        total_saved_secrets = 0

        for chunk in self.request.FILES['file'].chunks():
            chunk_txt = chunk.decode("UTF-8", errors="ignore")
            last_newline = chunk_txt.rfind("\n")

            chunk_main = previous_chunk + chunk_txt[:last_newline]
            if form.cleaned_data['type'] == 'grep':
                saved_hashes, saved_secrets = extract_creds(chunk_main, default_system=form.cleaned_data['system'])
            elif form.cleaned_data['type'] == 'keepass':
                saved_hashes, saved_secrets = self.parse_keepass_csv(chunk_main, form.cleaned_data['file'].name)
            elif form.cleaned_data['type'] == 'user:hash':
                saved_hashes, saved_secrets = self.parse_user_hash(chunk_main, form.cleaned_data['system'], form.cleaned_data['hash_type'])
            elif form.cleaned_data['type'] == 'user:secret':
                saved_hashes, saved_secrets = self.parse_user_secret(chunk_main, form.cleaned_data['system'])
            elif form.cleaned_data['type'] == 'user:hash:secret':
                saved_hashes, saved_secrets = self.parse_user_hash_secret(chunk_main, form.cleaned_data['system'], form.cleaned_data['hash_type'])
            elif form.cleaned_data['type'] == 'pwdump':
                saved_hashes, saved_secrets = self.parse_pwdump(chunk_main, form.cleaned_data['system'])
            else:
                raise forms.ValidationError("Invalid upload type")

            previous_chunk = chunk_txt[last_newline:]
            total_saved_hashes += saved_hashes
            total_saved_secrets += saved_secrets

        # Handle final part of upload between last newline and EOF
        if previous_chunk:
            if form.cleaned_data['type'] == 'grep':
                saved_hashes, saved_secrets = extract_creds(previous_chunk, default_system=form.cleaned_data['system'])
            elif form.cleaned_data['type'] == 'keepass':
                saved_hashes, saved_secrets = self.parse_keepass_csv(previous_chunk, form.cleaned_data['file'].name)
            elif form.cleaned_data['type'] == 'user:hash':
                saved_hashes, saved_secrets = self.parse_user_hash(previous_chunk, form.cleaned_data['system'], form.cleaned_data['hash_type'])
            elif form.cleaned_data['type'] == 'user:secret':
                saved_hashes, saved_secrets = self.parse_user_secret(previous_chunk, form.cleaned_data['system'])
            elif form.cleaned_data['type'] == 'user:hash:secret':
                saved_hashes, saved_secrets = self.parse_user_hash_secret(previous_chunk, form.cleaned_data['system'], form.cleaned_data['hash_type'])
            elif form.cleaned_data['type'] == 'pwdump':
                saved_hashes, saved_secrets = self.parse_pwdump(previous_chunk, form.cleaned_data['system'])
            else:
                raise forms.ValidationError("Invalid upload type")

        total_saved_hashes += saved_hashes
        total_saved_secrets += saved_secrets

        return redirect(reverse_lazy('event_tracker:credential-dump-upload-done',
                                     kwargs={'task_id': self.kwargs['task_id'],
                                             'saved_hashes': total_saved_hashes,
                                             'saved_secrets': total_saved_secrets}))

    def parse_keepass_csv(self, chunk_main, filename) -> tuple[int, int]:
        buffer = io.StringIO(chunk_main.encode('latin-1', 'backslashreplace').decode('unicode-escape'))
        reader = csv.DictReader(buffer, ['Account', 'Login Name', 'Password', 'Web Site', 'Comments'])
        saved_secrets = 0

        for row in reader:
            if row['Login Name'] == 'Login Name':
                pass  # This is the header from the first chunk, ignore
            elif row['Account'] in ["Sample Entry", "Sample Entry #2"]:
                pass  # These are prepopulated in KeePass, ignore
            else:
                if row["Login Name"]:
                    parts = row["Login Name"].split("\\", 2)
                else:
                    parts = ['?']

                if len(parts) > 1:
                    system = parts[0]
                    account = parts[-1]
                else:
                    system = None
                    account = parts[0]

                saved_cred, created = Credential.objects.get_or_create(source=f"KeePass import ({filename})",
                                                 system=system, account=account, secret=row["Password"],
                                                 purpose=f"{row['Account']}{' : ' if row['Comments'] else ''}{row['Comments']}{' : ' if row['Web Site'] else ''}{row['Web Site']}")
                if created:
                    saved_secrets += 1

            return 0, saved_secrets

    def parse_user_hash(self, chunk, system, hash_type) -> tuple[int, int]:
        creds_to_add = []

        for line in chunk.split("\n"):
            line = line.strip()
            try:
                account, account_hash = line.split(":", 1)
                if '\\' in account:
                    system_to_save, account = account.split('\\', 1)
                else:
                    system_to_save = system

                if account and account_hash:  # Check we don't have a line starting or ending with a :
                    creds_to_add.append(Credential(source="User:Hash import", system=system_to_save, account=account,
                                                 hash_type=hash_type, hash=account_hash))
            except ValueError:
                if line:
                    print(f"Skipping: {line}")

        # A before and after count may be incorrect if other users are concurrently modifying the table,
        # but it's the best we have given the bulk operations don't return meaningful objects.
        pre_insert_count = Credential.objects.count()
        Credential.objects.bulk_create(creds_to_add, ignore_conflicts=True)
        return Credential.objects.count() - pre_insert_count, 0

    def parse_user_secret(self, chunk, system) -> tuple[int, int]:
        creds_to_add = []

        for line in chunk.split("\n"):
            line = line.strip()
            try:
                account, account_secret = line.split(":", 1)
                if '\\' in account:
                    system_to_save, account = account.split('\\', 1)
                else:
                    system_to_save = system

                if account and account_secret:  # Check we don't have a line starting or ending with a :
                    creds_to_add.append(Credential(source="User:Secret import", system=system_to_save, account=account,
                                                 secret=account_secret))
            except ValueError:
                if line:
                    print(f"Skipping: {line}")

        # A before and after count may be incorrect if other users are concurrently modifying the table,
        # but it's the best we have given the bulk operations don't return meaningful objects.
        pre_insert_count = Credential.objects.count()
        Credential.objects.bulk_create(creds_to_add, ignore_conflicts=True)
        return 0, Credential.objects.count() - pre_insert_count

    def parse_user_hash_secret(self, chunk, system, hash_type) -> tuple[int, int]:
        creds_to_add = []

        for line in chunk.split("\n"):
            line = line.strip()
            try:
                account, account_hash, account_secret = line.split(":", 2)
                if '\\' in account:
                    system_to_save, account = account.split('\\', 1)
                else:
                    system_to_save = system

                if account and account_hash and account_secret:  # Check we don't have a line starting or ending with a :
                    creds_to_add.append(Credential(source="User:Hash:Secret import", system=system_to_save, account=account,
                                                 secret=account_secret, hash_type=hash_type, hash=account_hash))
            except ValueError:
                if line:
                    print(f"Skipping: {line}")

        # A before and after count may be incorrect if other users are concurrently modifying the table,
        # but it's the best we have given the bulk operations don't return meaningful objects.
        pre_insert_count = Credential.objects.count()
        Credential.objects.bulk_create(creds_to_add, ignore_conflicts=True)
        new_count = Credential.objects.count() - pre_insert_count
        return new_count, new_count

    def parse_pwdump(self, chunk, default_system) -> tuple[int, int]:
        creds_to_add = []

        for line in chunk.split("\n"):
            line = line.strip()
            try:
                account, rid, lmhash, nthash = line.split(":", 3)
                nthash = nthash.rstrip(":")

                if account:  # Check we don't have a line starting with a :
                    if "\\" in account:
                        system, account = account.split("\\", 1)
                    else:
                        system = default_system

                    if lmhash != "NO LM-HASH**********************" and lmhash.lower() != "aad3b435b51404eeaad3b435b51404ee":
                        creds_to_add.append(Credential(source="Pwdump import", system=system, account=account,
                                                       hash_type=HashCatMode.LM, hash=lmhash, purpose=f"Windows Login RID: {rid}"))
                    creds_to_add.append(Credential(source="Pwdump import", system=system, account=account,
                                                   hash_type=HashCatMode.NTLM, hash=nthash, purpose=f"Windows Login RID: {rid}"))
            except ValueError:
                if line:
                    print(f"Skipping: {line}")

        # A before and after count may be incorrect if other users are concurrently modifying the table,
        # but it's the best we have given the bulk operations don't return meaningful objects.
        pre_insert_count = Credential.objects.count()
        Credential.objects.bulk_create(creds_to_add, ignore_conflicts=True)
        return Credential.objects.count() - pre_insert_count, 0
