"""Reversible desktop accessibility setting for disposable Linux journeys."""
from verify_candidate import command


class ToolkitSetting:
    def __init__(self, environment):
        self.environment = environment
        self.original = None

    def read(self):
        value = command(['gsettings', 'get', 'org.gnome.desktop.interface',
                         'toolkit-accessibility'], self.environment).strip()
        if value not in ('true', 'false'):
            raise RuntimeError('desktop accessibility setting is not a boolean')
        return value

    def write(self, value):
        command(['gsettings', 'set', 'org.gnome.desktop.interface',
                 'toolkit-accessibility', value], self.environment)
        if self.read() != value:
            raise RuntimeError('desktop accessibility setting did not persist')

    def enable(self):
        self.original = self.read()
        self.write('true')

    def restore(self):
        if self.original is not None:
            self.write(self.original)
