"""Comparison of expected (SCL) and observed (PCAP) IEC 61850 models."""
from analyzer.result import Issue


def compare_models(expected, observed):
    """Compare SCL expectations with PCAP observations.

    Missing observations are ERRORs.  The comparison never creates missing
    objects in the observed model and never treats absent evidence as proof of
    presence.
    """
    issues = [Issue(
        'INFO', 'CMP-001', '-', 'Comparison',
        f'Expected model: {expected.source_type} ({expected.source_name}); '
        f'observed model: {observed.source_type} ({observed.source_name}).'
    )]

    expected_ids = _identifiers(expected)
    observed_ids = _identifiers(observed)

    for item in sorted(expected_ids - observed_ids):
        issues.append(Issue(
            'ERROR', 'CMP-002', '-', item,
            'Object is declared by the expected model but was not observed in the PCAP discovery.'
        ))

    for item in sorted(observed_ids - expected_ids):
        issues.append(Issue(
            'INFO', 'CMP-003', '-', item,
            'Identifier was observed in the PCAP discovery but is not present in the expected SCL model.'
        ))

    # An incomplete observation must not be silently downgraded to a normal
    # comparison. The PCAP analyzer reports the missing discovery stages; this
    # additional result makes the comparison itself explicit.
    evidence = getattr(observed, 'discovery_evidence', {})
    required = ('getServerDirectory', 'getLogicalNodeDirectory', 'getDataDirectory', 'getVariableAccessAttributes', 'getDataSetDirectory')
    missing = [k for k in required if not evidence.get(k, False)]
    if missing:
        issues.append(Issue(
            'ERROR', 'CMP-004', '-', 'PCAP discovery',
            'PCAP discovery is incomplete; the supplied capture cannot be accepted as complete evidence.'
        ))

    if not expected_ids:
        issues.append(Issue('ERROR', 'CMP-005', '-', 'Expected model',
                             'No normalized identifiers were available in the expected model.'))
    if not observed_ids:
        issues.append(Issue('ERROR', 'CMP-006', '-', 'Observed model',
                             'No normalized identifiers were observed in the PCAP discovery.'))
    return issues


def _identifiers(model):
    observed = getattr(model, 'observed_identifiers', None)
    if observed is not None:
        return {str(x) for x in observed if x}

    out = set()
    for ied in getattr(model, 'ieds', []):
        if getattr(ied, 'name', None):
            out.add(f'IED:{ied.name}')
        for ap in getattr(ied, 'access_points', []):
            for server in getattr(ap, 'servers', []):
                for ld in getattr(server, 'l_devices', []):
                    if getattr(ld, 'inst', None):
                        out.add(f'LD:{ld.inst}')
                    for ln in getattr(ld, 'all_logical_nodes', []):
                        out.add(f'LN:{ln.identifier}')
    return out
