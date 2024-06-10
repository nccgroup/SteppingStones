# Installation

Copy the `ssbot.service` & `steppingstones.service` into `/etc/systemd/system/`

## Service Control

From a command prompt:

* Start both the services:
  * `sudo service ssbot start`
  * `sudo service steppingstones start`
* If you want to have the services start automatically on next boot:
  * `sudo systemctl enable ssbot.service`
  * `sudo systemctl enable steppingstones.service`

Monitor the live application logs with `journalctl -f`