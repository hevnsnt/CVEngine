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
    """Like ``yaml.safe_load`` for a template: raises ``yaml.YAMLError`` on any anchor or alias, and on a value the loader cannot build."""
    try:
        return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - a SafeLoader subclass
    except (ValueError, TypeError, OverflowError) as exc:
        raise unbuildable(exc) from None


def unbuildable(exc):
    """A ``yaml.YAMLError`` for a scalar the safe loader parsed but could not build: ``2026-13-45`` is read as a date and fails in the date
    constructor with a ``ValueError`` that callers catching ``yaml.YAMLError`` (for the template's AI or feed text, or a person's input) do not
    expect, so the request or task failed with a 500 instead of saying the YAML is not valid."""
    return yaml.constructor.ConstructorError(None, None, f'a value cannot be read: {str(exc)[:120]}', None)
