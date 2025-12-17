import json
from datetime import datetime
from functools import cmp_to_key
from typing import Optional

from django import forms
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import HttpRequest, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import View
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.generic import ListView, TemplateView, CreateView, UpdateView, DeleteView, FormView
from neo4j.exceptions import ServiceUnavailable

from event_tracker.models import BloodhoundServer, HashCatMode, Credential
from event_tracker.signals import get_driver_for


def domain_name_comparer(domain_a, domain_b) -> bool:
    if domain_a.count(".") != domain_b.count("."):
        return domain_a.count(".") - domain_b.count(".")
    elif domain_a < domain_b:
        return -1
    elif domain_a > domain_b:
        return 1
    else:
        return 0


class BloodhoundStatsFilter(forms.Form):
    class Media:
        js = ["scripts/ss-forms.js"]

    def __init__(self, **kwargs):
        super(BloodhoundStatsFilter, self).__init__(**kwargs)

        domains = set()

        for bloodhound_server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(bloodhound_server):
                try:
                    with driver.session() as session:
                        domains.update(session.execute_read(_get_distinct_domains))
                except ServiceUnavailable:
                    print("Timeout talking to neo4j for domain filter")

        choices = [('', f"All domains")]
        choices += sorted(list(zip(domains, domains)), key=cmp_to_key(domain_name_comparer))
        self.fields['domain'] = forms.ChoiceField(choices=choices, required=False,
                                                  widget=forms.Select(attrs={'class': 'form-select form-select-sm submit-on-change'}))


def _get_distinct_domains(tx):
    domains = set()

    result = tx.run("MATCH (n:Base) return collect(distinct toLower(n.domain))")
    for domain in result:
        domains.update(domain[0])

    return domains

def get_bh_users(tx, q):
    users = set()

    if q:
        result = tx.run('match (n) where (n:User or n:AZUser) and toLower(split(n.name, "@")[0]) CONTAINS toLower($q) return split(n.name, "@")[0] limit 50', q=q)
        for record in result:
            users.add(record[0])

    return users


def get_bh_hosts(tx, q):
    hosts = set()

    if q:
        result = tx.run('match (n) where (n:Computer or n:AZDevice) and toLower(split(n.name, ".")[0]) CONTAINS toLower($q) return split(n.name, ".")[0] limit 50', q=q)
        for record in result:
            hosts.add(record[0])

    return hosts


class BloodhoundServerListView(PermissionRequiredMixin, ListView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    model = BloodhoundServer
    ordering = ['neo4j_connection_url']


def _get_kerberoastables(tx, domain: Optional[str]):
    if domain:
        return tx.run("""
            match (n:User) where 
                n.domain = $system and 
                n.hasspn=true  and
                n.enabled=true
            OPTIONAL MATCH shortestPath((n:User)-[:MemberOf]->(g:Group)) WHERE g.highvalue=true 
            return 
                toLower(n.name), toLower(g.name)
            order by n.name""", system=domain.upper()).values()
    else:
        return tx.run("""
            match (n:User) where 
                n.hasspn=true and
                n.enabled=true
            OPTIONAL MATCH shortestPath((n:User)-[:MemberOf]->(g:Group)) WHERE g.highvalue=true 
            return 
                toLower(n.name), toLower(g.name)
            order by n.domain, n.name""").values()


def _get_asreproastables(tx, domain: Optional[str]):
    if domain:
        return tx.run("""
            match (n:User) where 
                n.domain = $system and 
                n.dontreqpreauth=true and
                n.enabled=true
            OPTIONAL MATCH shortestPath((n:User)-[:MemberOf]->(g:Group)) WHERE g.highvalue=true 
            return 
                toLower(n.name), toLower(g.name)
            order by n.name""", system=domain.upper()).values()
    else:
        return tx.run("""
           match (n:User) where 
                n.dontreqpreauth=true and
                n.enabled=true
            OPTIONAL MATCH shortestPath((n:User)-[:MemberOf]->(g:Group)) WHERE g.highvalue=true 
            return 
                toLower(n.name), toLower(g.name)
            order by n.domain, n.name""").values()


def _get_recent_os_distribution(tx, domain: Optional[str], most_recent_machine_login):
    if domain:
        return tx.run("match (n:Computer) where n.domain = $system and n.lastlogontimestamp > $most_recent_machine_login - 2628000 return n.operatingsystem as os, count(n.operatingsystem) as freq order by os",
                      system=domain.upper(), most_recent_machine_login=most_recent_machine_login).values()
    else:
        return tx.run(
            "match (n:Computer) where n.lastlogontimestamp > $most_recent_machine_login - 2628000 return n.operatingsystem as os, count(n.operatingsystem) as freq order by os desc",
            most_recent_machine_login=most_recent_machine_login).values()


def _get_most_recent_machine_login(tx, domain: Optional[str]):
    if domain:
        return tx.run("match (n:Computer) where n.domain = $system return max(n.lastlogontimestamp)", system=domain.upper()).single()[0]
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
    match (n) where reverse(split(replace(n.distinguishedname, "\\\\,", "%5c%2c"), ','))[$parent_len] is not null and 
           reverse(split(replace(n.distinguishedname, "\\\\,", "%5c%2c"), ','))[0..$parent_len] = $parent
    return distinct reverse(split(replace(n.distinguishedname, "\\\\,", "&comma;"), ','))[$parent_len] as nodetext, 
           reverse(split(replace(n.distinguishedname, "\\\\,", "%5c%2c"), ','))[0..$node_len] as nodepath,
           count(*) as childcount,
           not max(size(split(replace(n.distinguishedname, "\\\\,", "%5c%2c"), ',')) > $node_len) as isleaf,
           collect(distinct labels(n)) as labs,
           true in collect(n.owned) as owned
    order by left(nodetext, 3) <> "DC=", isleaf, toLower(split(nodetext, '=')[-1])""", parent=parent, parent_len=len(parent), node_len=len(parent) + 1)

    return children.fetch(100_000)


class BloodhoundServerOUAPI(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_bloodhoundserver'

    def get(self, request: HttpRequest, *args, **kwargs):
        result = []

        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    children = session.execute_read(_get_dn_children, request.GET["id"].split(","))

                    for nodetext, nodepath, childcount, isleaf, types, owned in children:
                        try:
                            if nodetext[:2] == "DC":
                                nodetype = "globe"
                            elif not isleaf:
                                nodetype = "folder"
                            else:
                                nodetype = types[0][0].lower()
                        except:
                            nodetype = "unknown"

                        if owned and nodetype in ['user', 'computer', 'folder']:
                            nodetype += "-owned"

                        result.append({'id': nodepath,
                                       'parent': request.GET["id"],
                                       'text': f"{nodetext}{' (' + str(childcount) + ')' if not isleaf else ''}",
                                       'children': not isleaf,
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


class BloodhoundServerStatsView(PermissionRequiredMixin, FormView):
    permission_required = 'event_tracker.view_bloodhoundserver'
    template_name = 'event_tracker/bloodhoundserver_stats.html'
    form_class = BloodhoundStatsFilter

    def get_initial(self):
        """
        Merge the session stored filter into the form's initial state
        """
        initial = super().get_initial()
        initial.update(self.request.session.get("bloodhoundstatsfilter", default={}))
        return initial

    def form_valid(self, form):
        self.request.session['bloodhoundstatsfilter'] = form.cleaned_data
        return self.render_to_response(self.get_context_data())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        statsfilter = self.request.session.get('bloodhoundstatsfilter', {})
        domain = statsfilter.get("domain", None) or None

        kerberosoatable_hashtypes = [HashCatMode.Kerberos_5_TGSREP_RC4,
                                     HashCatMode.Kerberos_5_TGSREP_AES128,
                                     HashCatMode.Kerberos_5_TGSREP_AES256]

        asreproastable_hashtypes = [HashCatMode.Kerberos_5_ASREP_RC4]

        os_distribution = {}
        os_distribution_query = {}
        kerberoastable_users = {}
        kerberoastable_ticket_count = 0
        kerberoastable_cracked_count = 0
        kerberoastable_domains = set()

        asreproastable_users = {}
        asreproastable_ticket_count = 0
        asreproastable_cracked_count = 0
        asreproastable_domains = set()

        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    try:
                        # Machine OS
                        most_recent_machine_login = session.execute_read(_get_most_recent_machine_login, domain)
                        if most_recent_machine_login:
                            results = session.execute_read(_get_recent_os_distribution, domain,
                                                           int(most_recent_machine_login))
                            for result in results:
                                if not result[0]:
                                    continue
                                if result[0] not in os_distribution:
                                    os_distribution[result[0]] = 0
                                    os_distribution_query[result[0]] = (f'MATCH (n:Computer) WHERE n.lastlogontimestamp > {int(most_recent_machine_login) - 2628000} AND n.operatingsystem = {json.dumps(result[0])}' +
                                                                        (f' AND n.domain = {json.dumps(domain.upper())}' if domain else '') +
                                                                        f' RETURN n')
                                os_distribution[result[0]] += result[1]
                        # Kerberoastables
                        results = session.execute_read(_get_kerberoastables, domain)
                        for result in results:
                            user_parts = result[0].split('@')
                            username = user_parts[0].lower()
                            domain = user_parts[1].lower()
                            kerberoastable_domains.add(domain)

                            credential_obj_query = Credential.objects.filter(account__iexact=username, hash_type__in=kerberosoatable_hashtypes)
                            if domain:
                                credential_obj_query = credential_obj_query.filter(system__iexact=domain)

                            credential_obj = credential_obj_query.order_by("hash_type").first()
                            kerberoastable_users[username] = {"credential": credential_obj,
                                                              "high_value_group": result[1],
                                                              "domain": domain}

                            if credential_obj:
                                kerberoastable_ticket_count += 1
                                if credential_obj.secret:
                                    kerberoastable_cracked_count += 1

                        # ASREP roastable users
                        results = session.execute_read(_get_asreproastables, domain)
                        for result in results:
                            user_parts = result[0].split('@')
                            username = user_parts[0].lower()
                            domain = user_parts[1].lower()
                            asreproastable_domains.add(domain)

                            credential_obj_query = Credential.objects.filter(account__iexact=username,
                                                                             hash_type__in=asreproastable_hashtypes)
                            if domain:
                                credential_obj_query = credential_obj_query.filter(system__iexact=domain)

                            credential_obj = credential_obj_query.order_by("hash_type").first()
                            asreproastable_users[username] = {"credential": credential_obj,
                                                              "high_value_group": result[1],
                                                              "domain": domain}
                            if credential_obj:
                                asreproastable_ticket_count += 1
                                if credential_obj.secret:
                                    asreproastable_cracked_count += 1
                    except Exception as e:
                        print(f"Skipping {server} due to {e}")

        context["os_distribution"] = os_distribution
        context["os_distribution_query"] = os_distribution_query
        context["kerberoastable_users"] = kerberoastable_users
        context["kerberoastable_ticket_count"] = kerberoastable_ticket_count
        context["kerberoastable_cracked_count"] = kerberoastable_cracked_count
        context["kerberoastable_domain_count"] = len(kerberoastable_domains)
        context["asreproastable_users"] = asreproastable_users
        context["asreproastable_ticket_count"] = asreproastable_ticket_count
        context["asreproastable_cracked_count"] = asreproastable_cracked_count
        context["asreproastable_domain_count"] = len(asreproastable_domains)
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


class BloodhoundServerOUSearchAPI(PermissionRequiredMixin, View):
    permission_required = 'event_tracker.view_bloodhoundserver'

    def get(self, request: HttpRequest, *args, **kwargs):
        query = request.GET.get('q', '').strip()
        results = []
        limit = 50
        if not query:
            return JsonResponse({'results': [], 'truncated': False})

        for server in BloodhoundServer.objects.filter(active=True).all():
            if driver := get_driver_for(server):
                with driver.session() as session:
                    cypher = '''
                    MATCH (n)
                    WHERE (
                        (n:OU OR n:User OR n:Computer OR n:Group)
                        AND (
                            toLower(n.name) CONTAINS toLower($q)
                            OR (n.description IS NOT NULL AND toLower(n.description) CONTAINS toLower($q))
                            OR (n.objectid IS NOT NULL AND toLower(n.objectid) CONTAINS toLower($q))
                        )
                    )
                    RETURN labels(n)[0] as type, n.name as name, n.distinguishedname as distinguishedname, n.objectid as sid
                    LIMIT $limit
                    '''
                    for record in session.run(cypher, q=query, limit=limit):
                        results.append({
                            'type': record['type'],
                            'name': record['name'],
                            'distinguishedname': record['distinguishedname'],
                            'sid': record['sid'],
                            'server_id': server.id,
                        })
        truncated = len(results) >= limit
        return JsonResponse({'results': results, 'truncated': truncated})
