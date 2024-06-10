from django.contrib import admin

# Register your models here.
from cobalt_strike_monitor.models import TeamServer, Listener, Beacon, Archive, BeaconLog

admin.site.register(TeamServer)
admin.site.register(Listener)
admin.site.register(Beacon)
admin.site.register(Archive)
admin.site.register(BeaconLog)
