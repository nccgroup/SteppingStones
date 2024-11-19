# Plugins

SteppingStones provides a number of extension points which can be used to add custom functionality to the project. 
These are known as PluginPoints by the [plugin framework](https://pypi.org/project/django-plugins-bihealth/) 
(Docs: https://django-plugins.readthedocs.io/en/latest/). Examples can be found within the various `*-reports` apps 
included with the Stepping Stones project.

## Getting Started

To create a new plugin, first use the standard Django tools to create a new Django app:

```shell
python manage.py startapp my_plugin_name
```

Within the app add a `plugins.py` file and add one or more classes that extend the PluginPoints below.

Add the new Django App to the `INSTALLED_APPS` list in `stepping_stones\settings.py`

Run the Django plugins command to add the newly defined plugins to the database so Stepping Stones can find it:

```shell
python manage.py startapp my_plugin_name
```

## Plugin Points

### Reporting

#### EventReportingPluginPoint

A plugin point for a class which generates reports based on events in the main SteppingStones event database.

#### CredentialReportingPluginPoint

A plugin point for a class which generates reports based on credentials in the main Stepping Stones credential database.

### Background Tasks

#### BackgroundTaskPluginPoint

Used to start a background thread when SteppingStones starts. Task runs under the "ssbot" process / service.

##### Member Variables:

delay_seconds
: The number of seconds after SteppingStones starts to wait before running the initial background task. 30 (default)
means wait 30 seconds for SteppingStones to fully start before attempting to start the task.

repeat_seconds
: The number of seconds that should pass between invocations. 0 (default) means only run once.

replace_existing_tasks
: Boolean - True (default) means evict any previously scheduled tasks and only honour the delay/repeat values from now.

schedule_function
: A function pointer to the task to start. The function must:

* Be defined outside any classes (because the cls/self state can not be serialised)
* Be defined inside a file named `tasks.py` in the root of the plugin's Django application (to ensure the background task runner can find & import the function)
* Use the `background_task.background` decorator from [Django 4 Background Tasks](https://django4-background-tasks.readthedocs.io/en/latest/)


