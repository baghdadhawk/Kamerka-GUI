"""Pure family-selection logic for Shodan searches: resolving a family key to
its query/category, expanding the "search every family" sentinel, combining
per-category selections into one de-duplicated list, and the opt-in
port-grouping optimization.

Moved out of kamerka/tasks.py verbatim (no logic changed). None of this
module does any I/O or touches Celery/Shodan, so it is safe to import from
anywhere and to unit test directly.
"""
from kamerka.discovery.queries import (
    attackers_infra_queries,
    coordinates_queries,
    healthcare_queries,
    ics_queries,
)

# Sentinel value used by the search UI/forms to mean "every family in this
# category", e.g. selecting it in the ICS multiselect expands to every key of
# ics_queries. Handled by expand_families()/build_family_selection() below.
ALL_FAMILIES = "__all__"

# Category name -> the dict of family-key -> Shodan query string it draws from.
# Coordinates searches are intentionally not part of this mapping: they remain
# a separate flow (see shodan_search) and are not combined with a country
# search in a single Search row.
_CATEGORY_QUERY_DICTS = {
    "healthcare": healthcare_queries,
    "ics": ics_queries,
    "infra": attackers_infra_queries,
}


def resolve_family(key, category_hint=None):
    """Look up a family key and return (query, category), or None if unknown.

    If category_hint is given ('healthcare' / 'ics' / 'infra'), only that
    category's dict is checked (this disambiguates keys that happen to exist
    in more than one dict). Otherwise every known category is checked.
    """
    if category_hint is not None:
        d = _CATEGORY_QUERY_DICTS.get(category_hint)
        if d and key in d:
            return d[key], category_hint
        return None

    for category, d in _CATEGORY_QUERY_DICTS.items():
        if key in d:
            return d[key], category
    return None


def expand_families(keys, category):
    """Expand any ALL_FAMILIES sentinel in `keys` into every key of that
    category's query dict. Other keys are passed through unchanged. Order is
    preserved and duplicates are not removed here (build_family_selection
    de-duplicates the final result).
    """
    d = _CATEGORY_QUERY_DICTS.get(category, {})
    expanded = []
    for k in keys or []:
        if k == ALL_FAMILIES:
            expanded.extend(d.keys())
        else:
            expanded.append(k)
    return expanded


def build_family_selection(ics=None, healthcare=None, infra=None):
    """Combine per-category family selections (each possibly containing the
    ALL_FAMILIES sentinel) into a single, de-duplicated, ordered list of
    (key, query, category) tuples ready to be searched.

    - Expands "__all__" into every key of its category.
    - Drops unknown keys.
    - De-duplicates so the same (category, query) is only searched once, even
      if it was selected more than once (directly and/or via "__all__").

    This is a pure function (no I/O, no Celery/Shodan) so it can be unit
    tested directly.
    """
    selection = []
    seen = set()
    for category, keys in (("ics", ics), ("healthcare", healthcare), ("infra", infra)):
        for key in expand_families(keys, category):
            resolved = resolve_family(key, category_hint=category)
            if resolved is None:
                continue
            query, resolved_category = resolved
            dedup_key = (resolved_category, query)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            selection.append((key, query, resolved_category))
    return selection


# --- Opt-in port-grouping optimization (query-credit saver) ---------------
#
# Curated allowlist of ICS families that are identified by a protocol-specific
# port. Every port below belongs to exactly one family in this map, so a
# returned Shodan match's `port` unambiguously identifies which family it
# belongs to. This lets several of these families be searched together as one
# combined `port:a,b,c,...` query instead of one `api.search` call per family,
# cutting query credits from N down to 1 for the families involved.
#
# This is deliberately a short, hand-picked subset of ics_queries: the ports
# here are specific enough to their protocol that dropping the per-family
# product/string sub-filter (e.g. "product:Niagara") adds little noise. Noisy
# shared ports used by other ICS families (e.g. tank=10001, total_access=2000)
# are intentionally left out, since collapsing those would over-include
# unrelated devices that merely share the port.
GROUPABLE_PORT_FAMILIES = {
    "niagara": [1911, 4911],
    "dnp3": [20000],
    "hart": [5094],
    "pcworx": [1962],
    "iec": [2404],
    "proconos": [20547],
    "omron": [9600],
    "redlion": [789],
    "mitsubishi": [5006, 5007],
    "gestrip": [18245, 18246],
    "doors": [4070],
}

# Reverse lookup: port -> family key, derived from GROUPABLE_PORT_FAMILIES.
# Safe because every port above belongs to exactly one family.
PORT_TO_FAMILY = {
    port: family for family, ports in GROUPABLE_PORT_FAMILIES.items() for port in ports
}


def partition_groupable(selection):
    """Split a build_family_selection() result into (groupable, rest).

    `groupable` holds the (key, query, category) tuples whose category is
    "ics" and whose key is in GROUPABLE_PORT_FAMILIES (candidates for the
    combined port search). `rest` holds everything else (healthcare, infra,
    and any ICS family not in the curated allowlist), unchanged and in the
    same relative order as in `selection`.

    Pure function, no I/O, so it is unit-testable on its own.
    """
    groupable = []
    rest = []
    for key, query, category in selection:
        if category == "ics" and key in GROUPABLE_PORT_FAMILIES:
            groupable.append((key, query, category))
        else:
            rest.append((key, query, category))
    return groupable, rest
