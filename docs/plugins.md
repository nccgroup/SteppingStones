# Plugins

SteppingStones provides a number of extension points which can be used to add custom functionality to the project. 
These are known as PluginPoints by the [plugin framework](https://pypi.org/project/django-plugins-bihealth/) 
([Docs](https://django-plugins.readthedocs.io/en/latest/)). Examples can be found within the various `*-reports`
Django Apps included with the Stepping Stones project.

## Getting Started

To create a new plugin, first use the standard Django tools to create a new Django App:

```shell
python manage.py startapp my_plugin_name
```

Within the app add a `plugins.py` file and add one or more classes that extend the PluginPoints below.

Add the new Django App to the `INSTALLED_APPS` list in `stepping_stones\settings.py`

Run the Django plugins command to add the newly defined plugins to the database so Stepping Stones can find it:

```shell
python manage.py syncplugins
```

## PluginPoints

### UI Extensions

Adds menu options to pages in Stepping Stones to tie the plugin into the existing functionality. Useful for
bespoke reporting formats or plugin config pages.

#### Classes

##### EventReportingPluginPoint

A plugin point which will add a link under the "Reporting" button on the Events page. Useful for a class which 
generates reports based on events in the main SteppingStones event database.

##### CredentialReportingPluginPoint

A plugin point which will add a link under a "Reporting" button on the Credentials page. Useful for a class which
generates reports based on credentials in the main Stepping Stones credential database.

##### EventStreamSourcePluginPoint

A plugin point which will add a link under a "Sources" button on the EventStream page. Useful for allowing users to 
graphically configuring services that can populate the EventStream database.

#### Member Variables

title
: Required : a human-readable, short name for the plugin displayed on the plugin management pages. 

name
: Required : a slug used for building plugin URLs

category
: Required : The name of the section title in the drop down menu to add the link under. Can define a new category or 
use an existing one

icon_class
: Required : The FontAwesome CSS classes to use for the icon associated with the link, e.g. "fas fa-list-ul"

view_class
: Required : The Django class-based view to use as the entry point to the Plugin. The class should extend the 
PermissionRequiredMixin as the permissions are checked to ensure it is worth adding the link to the UI.

urls
: Required : A list similar to the `urlpatterns` found in `urls.py`, specifically for this plugin. The first entry in
list will be used for the link added to the Stepping Stones UI, additional entries can then be used to build mutli-page
plugins.

### Background Tasks

#### Classes

##### BackgroundTaskPluginPoint

Used to start a background thread when SteppingStones starts. Task runs under the "ssbot" process / service.

#### Member Variables

title
: Required : a human-readable, short name for the plugin displayed on the plugin management pages. 

name
: Required : a slug used for building plugin URLs

delay_seconds
: Optional : The number of seconds after Stepping Stones starts to wait before running the initial background task. 30 (default)
means wait 30 seconds for SteppingStones to fully start before attempting to start the task.

repeat_seconds
: Optional : The number of seconds that should pass between invocations. 0 (default) means only run once.

replace_existing_tasks
: Optional : a boolean value, True (default) means evict any previously scheduled tasks and only honour the delay/repeat values from now.

schedule_function
: Required : A function pointer to the task to start. The function must:

* Be defined outside any classes (because the cls/self state can not be serialised)
* Be defined inside a file named `tasks.py` in the root of the plugin's Django application (to ensure the background task runner can find & import the function)
* Use the `background_task.background` decorator from [Django 4 Background Tasks](https://django4-background-tasks.readthedocs.io/en/latest/)

