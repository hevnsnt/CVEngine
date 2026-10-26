"""YAML for untrusted nuclei templates (AI output, feed files). ``safe_load`` shares the node an alias points at, so a few hundred
bytes of nested anchors load instantly and then expand to billions of visits in any walker, or to a giant string in json.dumps.
A template never needs an anchor or an alias, so this loader refuses both."""
import yaml


class _NoAliasLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None) is not None:
            raise yaml.constructor.ConstructorError(None, None, 'anchors and aliases are not allowed in a template', event.start_mark)
        return super().compose_node(parent, index)


def load_template(text):
    """Like ``yaml.safe_load`` for a template: raises ``yaml.YAMLError`` on any anchor or alias."""
    return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - a SafeLoader subclass
