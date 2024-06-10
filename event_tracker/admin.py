from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from reversion.admin import VersionAdmin
from taggit_bulk.actions import tag_wizard

from .models import Task, Context, Event, AttackTactic, AttackTechnique, AttackSubTechnique, File, FileDistribution, \
    UserPreferences, Credential, Webhook

# Register your models here.

admin.site.register(Task)


@admin.register(Context)
class ContextAdmin(VersionAdmin):
    list_display = ["host", "user", "process"]


@admin.register(Event)
class EventAdmin(VersionAdmin):
    actions = [
        tag_wizard
    ]


@admin.register(FileDistribution)
class FileDistributionAdmin(VersionAdmin):
    pass


@admin.register(File)
class FileAdmin(VersionAdmin):
    list_display = ["filename", "md5_hash", "size"]

    def __repr__(self):
        return "XXX"


admin.site.register(Credential)
admin.site.register(Webhook)

admin.site.register(AttackTactic)
admin.site.register(AttackTechnique)
admin.site.register(AttackSubTechnique)

# Define an inline admin descriptor for Employee model
# which acts a bit like a singleton
class UserPreferencesInline(admin.StackedInline):
    model = UserPreferences
    can_delete = False
    verbose_name_plural = 'preferences'

# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = (UserPreferencesInline,)

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)