from django.core.management.base import BaseCommand

from cobalt_strike_monitor.models import Archive, TeamServer
from cobalt_strike_monitor.poll_team_server import clear_local_copy


class Command(BaseCommand):
    help = 'Erase all Cobalt Strike data from the database'

    def add_arguments(self, parser):
        # Optional argument
        parser.add_argument('-s', '--server', type=str, help='Name of the server to reset', )

    def handle(self, *args, **options):
        server = options['server']
        if server:
            server_obj = TeamServer.objects.get(description__iexact=server)
            self.stdout.write(f"Clearing {server_obj.description}")
            clear_local_copy(server_obj)
        else:
            self.stdout.write("Clearing all servers")
            for server in TeamServer.objects.all():
                clear_local_copy(server)

        self.stdout.write(self.style.SUCCESS('DONE'))
