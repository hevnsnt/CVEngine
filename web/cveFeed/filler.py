"""Template filler in text meant for a person.

A model that echoes the schema of its own answer writes \"Placeholder\" where a diagnosis belongs, and a status line or an alert that carries it shows
a word that says nothing. ``is_placeholder`` is the one test for that; ``cveFeed.reviewer.usable_note`` applies it to the reviewer's notes and
diagnoses, and the reviewer container (``cvengine_reviewer.guard.is_filler``) keeps the same rule on its side so filler is not even sent.
"""
import re

_FILLER_WORD = re.compile(r'\b(?:placeholder|lorem ipsum|tbd|todo|fixme|n/a|not applicable|undefined|null|none|string|text|sample|example|diagnosis|note)\b', re.I)
_TEMPLATE_SHAPE = re.compile(r'^\s*(?:[\[<{(].*[\]>})]|(?:insert|your|enter|add|write)\b.*\bhere|\.{3}|-+|x{3,})\s*[.!]?\s*$', re.I)


def is_placeholder(text):
    """Whether ``text`` is filler and not an answer: empty or one word, only filler words, a template shape (``<diagnosis>``, ``[your diagnosis here]``,
    ``...``), or lorem ipsum."""
    plain = ' '.join(str(text or '').split()).strip(' .!:;-')
    if not plain or ' ' not in plain:
        return True
    if _TEMPLATE_SHAPE.match(plain) or 'lorem ipsum' in plain.lower():
        return True
    return not re.sub(r'[\W_]+', ' ', _FILLER_WORD.sub('', plain)).strip()
