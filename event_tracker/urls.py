from django.urls import path

import event_tracker.views_credentials
from . import views
from .views import EventCreateView, EventUpdateView, EventDeleteView, EventListView, EventCloneView, ContextAutocomplete, CSVEventListView, TeamServerCreateView, \
    TeamServerUpdateView, TeamServerDeleteView, CSLogsListView, CSLogToEventView, CSUploadsListView, \
    FileAutocomplete, CSBeaconsListView, CSBeaconToEventView, FileListView, TeamServerListView, BeaconExclusionList, \
    BeaconExclusionDeleteView, WebhookListView, WebhookCreateView, WebhookUpdateView, WebhookDeleteView, \
    CSBeaconsTimelineView, beaconwatch_add, beaconwatch_remove, CSDownloadsListView, CSDownloadToEventView, \
    EventLatMoveCloneView, CSLogsListJSON, \
    BloodhoundServerListView, BloodhoundServerCreateView, BloodhoundServerUpdateView, BloodhoundServerDeleteView, \
    UserListAutocomplete, HostListAutocomplete, ProcessListAutocomplete, InitialConfigTask, InitialConfigAdmin, \
    toggle_event_star, EventTagAutocomplete, TeamServerConfigView, EventStreamListView, EventStreamListJSON, EventStreamUpload, \
    EventStreamToEventView, toggle_qs_stars, LimitedEventUpdateView, EventBulkEdit, \
    TeamServerHealthCheckView
from .views_credentials import CredentialListView, CredentialListJson, CredentialCreateView, CredentialUpdateView, \
    CredentialDeleteView, credential_wordlist, prefix_wordlist, suffix_wordlist, credential_uncracked_hashes, credential_masklist, prefix_masklist, suffix_masklist

app_name = "event_tracker"
urlpatterns = [
    path('', views.index, name='index'),

    path('<int:task_id>', EventListView.as_view(), name='event-list'),

    path('<int:task_id>/add/', EventCreateView.as_view(), name='event-add'),
    path('<int:task_id>/clone/<int:event_id>', EventCloneView.as_view(), name='event-clone'),
    path('<int:task_id>/lat-move-clone/<int:event_id>', EventLatMoveCloneView.as_view(), name='event-lat-move-clone'),
    path('<int:task_id>/<int:pk>/', EventUpdateView.as_view(), name='event-update'),
    path('<int:task_id>/<int:pk>/limited', LimitedEventUpdateView.as_view(), name='event-update-limited'),
    path('<int:task_id>/<int:pk>/toggle_star', toggle_event_star, name='event-toggle-star'),
    path('<int:task_id>/toggle_stars', toggle_qs_stars, name='toggle_qs_stars'),
    path('<int:task_id>/<int:pk>/delete/', EventDeleteView.as_view(), name='event-delete'),
    path('<int:task_id>/bulk_edit/', EventBulkEdit.as_view(), name='event-bulk-edit'),

    path('<int:task_id>/files', FileListView.as_view(), name='file-list'),

    path('<int:task_id>/creds', CredentialListView.as_view(), name='credential-list'),
    path('<int:task_id>/creds.json', CredentialListJson.as_view(), name='credential-list-json'),
    path('<int:task_id>/creds/add/', CredentialCreateView.as_view(), name='credential-add'),
    path('<int:task_id>/creds/<int:pk>/', CredentialUpdateView.as_view(), name='credential-update'),
    path('<int:task_id>/creds/<int:pk>/delete/', CredentialDeleteView.as_view(), name='credential-delete'),
    path('<int:task_id>/creds/wordlist', credential_wordlist, name='credential-wordlist'),
    path('<int:task_id>/creds/prefix-wordlist', prefix_wordlist, name='prefix-wordlist'),
    path('<int:task_id>/creds/suffix-wordlist', suffix_wordlist, name='suffix-wordlist'),
    path('<int:task_id>/creds/masklist/<int:min_len>', credential_masklist, name='credential-masklist'),
    path('<int:task_id>/creds/masklist/prefixes', prefix_masklist, name='prefix-masklist'),
    path('<int:task_id>/creds/masklist/suffixes', suffix_masklist, name='suffix-masklist'),
    path('<int:task_id>/creds/hashes/<int:hash_type>', credential_uncracked_hashes, name='credential-uncracked-hashes'),
    path('<int:task_id>/creds/hashes/cracked', event_tracker.views_credentials.UploadCrackedHashes.as_view(), name='credential-cracked-hashes-upload'),
    path('<int:task_id>/creds/hashes/cracked-done/<int:cracked_hashes>/<int:cracked_accounts>/', event_tracker.views_credentials.UploadCrackedHashesDone.as_view(), name='credential-cracked-hashes-upload-done'),
    path('<int:task_id>/creds/hashes', event_tracker.views_credentials.UploadHashes.as_view(), name='credential-hashes-upload'),
    path('<int:task_id>/creds/stats', event_tracker.views_credentials.CredentialStatsView.as_view(), name='credential-stats'),
    path('<int:task_id>/creds/stats/password-complexity-piechart.png', event_tracker.views_credentials.password_complexity_piechart, name='password-complexity-piechart'),
    path('<int:task_id>/creds/stats/password-structure-piechart.png', event_tracker.views_credentials.password_structure_piechart, name='password-structure-piechart'),
    path('<int:task_id>/creds/stats/password-length-chart.png', event_tracker.views_credentials.password_length_chart, name='password-length-chart'),
    path('<int:task_id>/creds/stats/password-age-chart.png', event_tracker.views_credentials.password_age_chart, name='password-age-chart'),

    path('<int:task_id>/reports/csv', CSVEventListView.as_view(), name='csv_export'),

    path('api/mitre/techniques-for/<str:tactic>', views.techniques_for_tactic),
    path('api/mitre/subtechniques-for/<str:technique>', views.subtechniques_for_technique),

    path(r'context-autocomplete/', ContextAutocomplete.as_view(), name='context-autocomplete'),
    path(r'file-autocomplete/', FileAutocomplete.as_view(), name='file-autocomplete'),
    path(r'eventtag-autocomplete/', EventTagAutocomplete.as_view(), name='eventtag-autocomplete'),

    path('team-server', TeamServerListView.as_view(), name='team-server-list'),
    path('team-server/config', TeamServerConfigView.as_view(), name='team-server-config'),
    path('team-server/add/', TeamServerCreateView.as_view(), name='team-server-add'),
    path('team-server/<int:pk>/', TeamServerUpdateView.as_view(), name='team-server-update'),
    path('team-server/<int:serverid>/healthcheck', TeamServerHealthCheckView.as_view(), name='team-server-healthcheck'),
    path('team-server/<int:pk>/delete/', TeamServerDeleteView.as_view(), name='team-server-delete'),

    path('cs-logs', CSLogsListView.as_view(), name='cs-logs-list'),
    path('cs-logs-api', CSLogsListJSON.as_view(), name='cs-logs-json'),
    path('cs-logs/<int:pk>/to_event/', CSLogToEventView.as_view(), name="cs-log-to-event"),
    path('cs-uploads', CSUploadsListView.as_view(), name='cs-uploads-list'),
    path('cs-downloads', CSDownloadsListView.as_view(), name='cs-downloads-list'),
    path('cs-downloads/<int:pk>/to_event/', CSDownloadToEventView.as_view(), name="cs-download-to-event"),
    path('cs-beacons', CSBeaconsListView.as_view(), name='cs-beacons-list'),
    path('cs-beacons/<int:pk>/to_event/', CSBeaconToEventView.as_view(), name="cs-beacon-to-event"),
    path('cs-beacons/create-exclusion', views.create_beacon_exclusion, name='cs-beacons-create-exclusion'),
    path('cs-beacons/exclusions', BeaconExclusionList.as_view(), name="cs-beacon-exclusion-list"),
    path('cs-beacons/exclusions/<int:pk>/delete/', BeaconExclusionDeleteView.as_view(), name="cs-beacon-exclusion-delete"),
    path('cs-beacon-timeline', CSBeaconsTimelineView.as_view(), name='cs-beacon-timeline'),
    path('cs-beaconwatch-add/<int:beacon_id>', beaconwatch_add, name='cs-beaconwatch-add'),
    path('cs-beaconwatch-remove/<int:beacon_id>', beaconwatch_remove, name='cs-beaconwatch-remove'),

    path('eventstream', EventStreamListView.as_view(), name='eventstream-list'),
    path('eventstream-api', EventStreamListJSON.as_view(), name='eventstream-json'),
    path('eventstream/add/', EventStreamUpload.as_view(), name='eventstream-upload'),
    path('eventstream/<int:pk>/to_event/', EventStreamToEventView.as_view(), name="eventstream-to-event"),

    path('webhooks', WebhookListView.as_view(), name='webhook-list'),
    path('webhooks/add/', WebhookCreateView.as_view(), name='webhook-add'),
    path('webhooks/<int:pk>/', WebhookUpdateView.as_view(), name='webhook-update'),
    path('webhooks/<int:pk>/delete/', WebhookDeleteView.as_view(), name='webhook-delete'),
    path('webhooks/<int:webhook_id>/trigger', views.trigger_dummy_webhook, name='webhook-manual-trigger'),

    path("backup", views.download_backup, name="backup"),

    path('bloodhound-server', BloodhoundServerListView.as_view(), name='bloodhound-server-list'),
    path('bloodhound-server/add/', BloodhoundServerCreateView.as_view(), name='bloodhound-server-add'),
    path('bloodhound-server/<int:pk>/', BloodhoundServerUpdateView.as_view(), name='bloodhound-server-update'),
    path('bloodhound-server/<int:pk>/delete/', BloodhoundServerDeleteView.as_view(), name='bloodhound-server-delete'),
    path('bloodhound-server/stats', views.BloodhoundServerStatsView.as_view(), name='bloodhound-stats'),
    path('bloodhound-server/ou', views.BloodhoundServerOUView.as_view(), name='bloodhound-ou'),
    path('bloodhound-server/node/<str:dn>', views.BloodhoundServerNode.as_view(), name='bloodhound-node'),
    path('bloodhound-server/toggle-high-value/<str:dn>', views.toggle_bloodhound_node_highvalue, name='bloodhound-node-toggle-highvalue'),
    path('bloodhound-server/ou-api', views.BloodhoundServerOUAPI.as_view(), name='bloodhound-ou-api'),

    path('host-list-autocomplete/', HostListAutocomplete.as_view(), name='host-list-autocomplete'),
    path('user-list-autocomplete/', UserListAutocomplete.as_view(), name='user-list-autocomplete'),
    path('process-list-autocomplete/', ProcessListAutocomplete.as_view(), name='process-list-autocomplete'),

    path('initial-config/task', InitialConfigTask.as_view(), name='initial-config-task'),
    path('initial-config/admin', InitialConfigAdmin.as_view(), name='initial-config-admin'),
]