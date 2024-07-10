# Stepping Stones

## Purpose

A hub for Red Team activity to aid in record keeping, situational awareness and reporting. 
Stepping Stones provides a web based UI for the team to log activity and generate report snippets. 
The UI is intended to be rapid enough to be used throughout the engagement, not just in the reporting phase.

[Release Blog Post](https://research.nccgroup.com/2024/06/12/stepping-stones-a-red-team-activity-hub/)

## Installation

Stepping Stones is a Python Django application, so to get a local copy running:

1) Install the latest version of Python 3 (tested with 3.12.2 on Windows and Linux)
2) Change into the root directory of a copy of this repository
3) Create a virtual environment to keep the dependencies separate from other apps: `python -m venv .venv`
4) Activate the virtual environment: `.venv\Scripts\activate` or `source .venv/bin/activate` on *nix
5) Install the dependencies: `pip install -r requirements.txt`
6) Ensure the 3rd party background tasks modules has all the required migrations:
`python manage.py makemigrations background_task`
7) Get the database schema up to date: `python manage.py migrate`
8) Start the application:
  * If running on a Linux system with systemd, see [systemd guide](systemd/README.md)
  * For dev versions:
    * Run `python manage.py runserver` and `python manage.py process_tasks` concurrently
  * For production versions:
    * Run `python manage.py check --deploy` to obtain lockdown advice, and then follow a guide such as: 
    https://docs.djangoproject.com/en/5.0/howto/deployment/
9) Visit the application to configure a task and an admin user: e.g. access <http://127.0.0.1:8000> if running locally
  * Note: The created user will also be used for the main app and shown as the "red team operator" against logged events, 
  so pick a suitable username, e.g. "ST", or "stephen", rather than "admin". If using the Cobalt Strike integration, 
  using the same usernames for both tools will aid integration.

### Cobalt Strike Integration

* Placed a LICENSED Cobalt Strike in /opt/cobaltstrike or c:\tools\cobaltstrike-dist\cobaltstrike
  
On the team server - punch a hole in the firewall to allow Stepping Stones to connect, e.g.
* On AWS, set the Stepping Stones security group to be allowed into 50050 on Team Server
* On host, ensure the firewall also allows traffic in, e.g. `sudo ufw allow proto tcp from 172.31.16.0/20 to any port 50050`


## Updating the Application

If running a local copy, when the code has been updated in git and you want the new features:

1) Stop both the services, e.g. with [systemd](systemd/README.md):
  * `sudo service ssbot stop`
  * `sudo service steppingstones stop`
2) Obtain the latest version, e.g. from <https://github.com/nccgroup/SteppingStones/archive/refs/heads/main.zip>
3) Unzip the download and copy the files over the top of the deployment, e.g. `rm -rf /tmp/stepping-stones-main; unzip /tmp/stepping-stones-main.zip && cp -R /tmp/stepping-stones-main/* /opt/steppingstones`
4) Activate the virtual environment (if not done so already) from the steppingstones directory: `.venv\Scripts\activate` or `source .venv/bin/activate` on *nix
5) Pull in any new dependencies with: `pip install -r requirements.txt`
6) Ensure the 3rd party background tasks modules has all the required migrations: `python manage.py makemigrations background_task`
7) Run any migration scripts to morph your local database into the new schema: `python manage.py migrate`. 
  * If Django prompts you to run `python manage.py makemigrations` then STOP and contact the Stepping Stones developers - it is important all users are working from the same set of migration scripts and these should be co-ordinated through the developers.
8) Restart both the services, e.g. with [systemd](systemd/README.md):
  * `sudo service ssbot restart`
  * `sudo service steppingstones restart`
9)  Ensure there are no errors, e.g. with [systemd](systemd/README.md) `journalctl -u steppingstones`

## Starting Again With A Clean Database

If you are using the same instance for different jobs and wish to archive the old data then start afresh you can:
* Perform step 1 from _Updating the Application_ above to stop the application
* Rename the SQLite database:
  * `mv db.sqlite3 db.sqlite.OLD_CLIENT_NAME`
* Perform steps 2,4 and 7-9 from _Installation_ above to create the correct database structure and access the freshly configured application.

## Backups

The system uses SQLite. Backup the db.sqlite3 file in the server's root or via the Web UI periodically to protect your valuable data.

## Web Hooks

The configured web hook URLs will each be sent a small JSON document on key events. 
The JSON document always has the structure:

```json
{
    "type": "notification type",
    "message": "Human readable message"
}
```

The `type` field can be one of:

* `new beacon` (A previously unseen beacon has connected to a monitored Team Server)
* `respawned beacon` (A previously seen beacon has connected to a monitored Team Server)
* `returned beacon` (A beacon that has been explicitly monitored for reconnection has just reconnected)

To consume this, you can use a https://make.com scenario, based on the following blueprint:

```json
{"name":"Webhook to iOS","flow":[{"id":1,"module":"gateway:CustomWebHook","version":1,"parameters":{"hook":129792,"maxResults":1},"mapper":{},"metadata":{"designer":{"x":-386,"y":-129},"restore":{"parameters":{"hook":{"data":{"editable":"true"},"label":"My webhook"}}},"parameters":[{"name":"hook","type":"hook:gateway-webhook","label":"Webhook","required":true},{"name":"maxResults","type":"number","label":"Maximum number of results"}],"interface":[{"name":"type","type":"text"},{"name":"message","type":"text"}]}},{"id":8,"module":"ios:SendNotification","version":1,"parameters":{"device":171760},"mapper":{"body":"{{1.message}}","title":"{{1.type}}","action":"","priority":10,"collapsible":false},"metadata":{"designer":{"x":-31,"y":-128},"restore":{"expect":{"action":{"label":"Default"},"priority":{"label":"Deliver immediately"}},"parameters":{"device":{"data":{"editable":"undefined"},"label":"Personal Phone"}}},"parameters":[{"name":"device","type":"device:apn","label":"Device","required":true}],"expect":[{"name":"title","type":"text","label":"Title","required":true},{"name":"body","type":"text","label":"Body"},{"name":"action","type":"select","label":"Action","validate":{"enum":["open_url"]}},{"name":"priority","type":"select","label":"Priority","required":true,"validate":{"enum":[10,5]}},{"name":"collapsible","type":"boolean","label":"Collapse push notifications","required":true}]}}],"metadata":{"instant":true,"version":1,"scenario":{"roundtrips":1,"maxErrors":3,"autoCommit":true,"autoCommitTriggerLast":true,"sequential":false,"confidential":false,"dataloss":false,"dlq":false},"designer":{"orphans":[]},"zone":"eu1.make.com"}}
```

Import the above blueprint by creating a blank scenario and using the "Import Blueprint" feature under the "..." (More) 
menu found in the bottom centre of the Web UI.

Two further steps are then required:
* Click the webhook circle and add a new named webhook to generate a URL
* Click the Apple logo to enroll an iPhone to make.com with their integromat app.

Webhooks can be tested via a button on the Stepping Stones webhook page.

## Security Model

Stepping Stones utilises Django's model level permission system, allowing users to be constrained from creating, editing, viewing and deleting each type of data model.
Groups can be found in the `/admin` console which assign a set of permissions, e.g. suitable for a Client's Blue Team, to any members of that group.

Existing groups are:

| Role                             | Description                                                                                        |
|----------------------------------|----------------------------------------------------------------------------------------------------|
| Client Blue Team - Read Only     | Can read the events and files page                                                                 |
| Client Blue Team - Limited Write | As per `Client Blue Team - Read Only` with write access to an Event's outcome and detection fields |


Users created during the installation process are given "superuser" status so implicitly have all possible permissions.
However, when manually creating users via the admin console ensure they are NOT marked as "staff" nor "superuser" so that they start with no implied permissions and will therefore only obtain permissions by being added to groups.

## Localisation

User's Time Zones can be modified via the `/admin` portal. Times in the reports are intentionally output in UTC to permit easier correlation by Blue Teams.

Date formats presented by Stepping Stones should match the web browser's locale. i.e. Users with whose browser is configured with a US locale will view dates in MM/DD/YYYY format in the web UI and report snippets.

## EventStream

Stepping Stones can ingest logs from other tools if they are formatted into the JSON based, bespoke EventStream format. The format is 
detailed within the web interface of SteppingStones, including schemas and example data.

Once an EventStream log has been ingested by Stepping Stones specific relevant entries can be cloned into Events for the report.

## Cobalt Strike Integration Details

The preferred method of integrating Cobalt Strike is via SSBot. This requires a licensed copy of Cobalt Strike in /opt/cobaltstrike or c:\tools\cobaltstrike-dist\cobaltstrike which will be used to contact any (enabled) team servers configured in the Web interface.

Once integrated:
* Source/Target dropdowns will include beacons
* File drop-downs will include files uploaded/downloaded via CS
* Credentials tab will populate based on tool output and any credentials added to CS.
* Individual CS actions can be turned into events - please be selective and add context to each event rather than duplicating actions wholesale to maintain report quality.

There are additional CLI commands which can be used if SSBot is not working as intended:

* `.\manage.py reset_cs_data [-s SERVER]` - Will reset any data parsed from the given team server, or all if no name is given. This will not affect data derived from the CS logs, e.g. manually cloned events or credentials.
* `.\manage.py parse_log_tar <file name>` - Will parse the contents of a logs directory, tar'ed up and taken from a team server. Note: this does not include all of the data accessible by SSBot and is therefore not the preferred ingest technique

## BloodHound Integration

Neo4j servers configured via the web UI will be used to:
* Update the BloodHound `owned` status when credentials get added with a password, or a beacon is run on a specific host as system.
* Populate the Source/Target dropdowns with users and computers
* Provide additional reporting on accounts in the credentials section of Stepping Stones

## Reporting Plugins

It is possible to create your own reports for events and credentials by extended existing reporting plugin points.
Plugins are built with [django-plugins](https://pypi.org/project/django-plugins-bihealth/) 
(Docs: https://django-plugins.readthedocs.io/en/latest/). Examples can be found within the various `*-reports` apps 
included with the Stepping Stones project.

Place your own reporting plugins in a Django App which should then be extracted into the deployed Stepping Stones 
Django Project and the new app included in the `INSTALLED_APPS` list within `stepping_stones\settings.py`.
