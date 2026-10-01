# Cobalt Strike

## Asynchronous

If the real-time log ingestion for Cobalt Strike is not an option, then it's possible to import the logs from the C2 
server manually.

On the Cobalt Strike server:
```commandline
tar cvfz cslogs.tar.gz /opt/cobaltstrike/server/logs
```

Copy the resulting `cslogs.tar.gz` file to the SteppingStones server, then in the virtual environment run:
```commandline
python .\manage.py parse_log_tar "Z:\download\path\cslogs.tar.gz"
```