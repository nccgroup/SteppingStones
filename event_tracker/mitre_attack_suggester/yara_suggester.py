import pathlib
import yara_x
import os
from django.utils.autoreload import autoreload_started

directory = pathlib.Path(__file__).parent / "yara-rules"


# Set up autoreloader to fire when *.yar files changes too
# Do this before we attempt to compile to avoid compilation errors breaking the autoreloader
def watch_yara_files(sender, *args, **kwargs):
    sender.watch_dir(directory, "*.yar")


autoreload_started.connect(watch_yara_files)

compiler = yara_x.Compiler(relaxed_re_syntax=True)

# Iterate over files in directory
with os.scandir(directory) as entries:
    for entry in entries:
        if entry.name.endswith('.yar') and entry.is_file():
            with open(os.path.join(directory, entry.name)) as f:
                compiler.add_source(f.read(), entry.path)


rules = compiler.build()


class YaraSuggester:

    def get_suggestions(self, raw_evidence):
        result = []
        yara_results = rules.scan(raw_evidence.encode('utf-8'))
        for match in yara_results.matching_rules:
            tactic = None
            technique = None
            for name, value in match.metadata:
                if name == 'mitre_att_tactic':
                    tactic = value
                elif name == 'mitre_att_technique':
                    technique = value

            # Must have a tactic, but technique is optional
            if tactic:
                result.append((tactic, technique))

        return result
