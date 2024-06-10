from djangoplugins.point import PluginPoint


# PluginPoint doesn't support multiple levels of inheritance, hence the copy & paste
class EventReportingPluginPoint(PluginPoint):
    category = "Undefined Category"
    icon_class = "fa-solid fa-notdef"
    view_class = None

    def entry_point_name(self):
        return f'{self.name}-entry-point'

    def is_access_permitted(self, user):
        if self.view_class:
            perms = self.view_class().get_permission_required()
            return user.has_perms(perms)
        else:
            return False


class CredentialReportingPluginPoint(PluginPoint):
    category = "Undefined Category"
    icon_class = "fa-solid fa-notdef"
    view_class = None

    def entry_point_name(self):
        return f'{self.name}-entry-point'

    def is_access_permitted(self, user):
        if self.view_class:
            perms = self.view_class().get_permission_required()
            return user.has_perms(perms)
        else:
            return False
