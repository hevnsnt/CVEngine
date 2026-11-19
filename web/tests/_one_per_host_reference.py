"""The correlated form of ``agentapi.services._one_per_host`` before it read each host's facts once (a copy, not imported: the reference
``tests.test_read_paths_batch`` compares the set-based form with). ``ArraySubquery`` is supplied by the test."""


def _one_per_host(qs, per_project=False):
    """Collapse a Subdomain queryset to one row per host. First one row per hostname: the one with the most open ports, then the most
    IPs, then the newest scan (a scan-less row last). Then names that resolve to exactly the same addresses (``example.com`` and
    ``www.example.com``) become one host: the project's own target name first, else the shortest name (see
    ``cveFeed.counts.with_host_key``; a name behind a CDN, or without an address, stays alone). Two Postgres DISTINCT ON passes over
    the filtered ids, then a plain ``id__in`` so ordering and paging stay ordinary. Richness comes from subqueries on a fresh
    queryset, so search joins cannot inflate the counts. ``per_project`` (the all-projects view) keeps one row per (project,
    hostname): the same name in two projects is two hosts."""
    from django.db.models import Case, Count, F, IntegerField, OuterRef, Subquery, Value, Window, When
    from django.db.models.functions import Coalesce, Collate, Length, RowNumber
    from cveFeed.counts import with_host_key
    from startScan.models import OPEN_PORT_STATES, Port, Subdomain
    ports = Port.objects.filter(state__in=OPEN_PORT_STATES, ports__ip_addresses=OuterRef('pk')).order_by() \
        .values('ports__ip_addresses').annotate(c=Count('id', distinct=True)).values('c')
    ips = Subdomain.ip_addresses.through.objects.filter(subdomain_id=OuterRef('pk')).order_by() \
        .values('subdomain_id').annotate(c=Count('id')).values('c')
    keys = ('target_domain__project_id', 'name') if per_project else ('name',)
    by_name = Subdomain.objects.filter(id__in=qs.order_by().values('id')).order_by(
        *keys, Coalesce(Subquery(ports), Value(0)).desc(), Coalesce(Subquery(ips), Value(0)).desc(),
        F('scan_history_id').desc(nulls_last=True), '-id').distinct(*keys).values('id')
    own_target = Case(When(name=F('target_domain__name'), then=Value(0)), default=Value(1), output_field=IntegerField())
    # names that tie on length are ordered by their bytes (COLLATE "C"), not by the database's locale: the same order on every database, and the one
    # ``cveFeed.inventory_counts`` takes in Python, so the host that stands for a group does not depend on how the database sorts text
    # a window rather than DISTINCT ON: the key is an annotation, which DISTINCT ON cannot keep once the query is cut to ids
    rep = with_host_key(Subdomain.objects.filter(id__in=by_name)).annotate(_rank=Window(
        RowNumber(), partition_by=[F('host_key')],
        order_by=[own_target.asc(), Length('name').asc(), Collate('name', 'C').asc(), Coalesce(Subquery(ports), Value(0)).desc(), F('id').desc()])
    ).filter(_rank=1).values('id')
    # the ids are gathered into an array once and looked up in it (``id = ANY(ARRAY(...))``). ``id IN (subquery)`` let Postgres guess one row for the
    # window query and rescan its 8,000 rows for each of 10,000 hosts: 4.8 s at that size, 0.1 s with the array
    return Subdomain.objects.filter(id__in_array=ArraySubquery(rep))
