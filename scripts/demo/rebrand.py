"""Copy a demo seed script with the tour's company names in place of the ones the CI UI gates use.

    python3 scripts/demo/rebrand.py scripts/demo/seed_demo.py OUT.py

scripts/demo/seed_demo.py and stage_live.py name the demo company Acme Corp (with Acme Labs and Harbor Foods beside it) because the CI UI gates
look those slugs up. Real companies trade under those names, so the README tour films a copy of the seed with every one of them replaced by an
invented name that no known company or product uses (checked with a web search when chosen). make_gif.sh runs this; the gates never do.
"""
import sys

# longest first, so 'Acme Corp' is replaced before 'Acme'
NAMES = [
    ('Acme Corp', 'Quillfern Group'), ('acme-corp', 'quillfern-group'),
    ('Acme Labs', 'Quillfern Labs'), ('acme-labs', 'quillfern-labs'),
    ('Harbor Foods', 'Grellbrook Foods'), ('harbor-foods', 'grellbrook-foods'), ('harborfoods', 'grellbrook'),
    ('Acme', 'Quillfern'), ('acme', 'quillfern'),
]


def rebrand(text):
    for old, new in NAMES:
        text = text.replace(old, new)
    return text


if __name__ == '__main__':
    src, out = sys.argv[1:3]
    with open(src, encoding='utf-8') as f:
        text = rebrand(f.read())
    with open(out, 'w', encoding='utf-8') as f:
        f.write(text)
