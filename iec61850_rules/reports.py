"""IEC 61850 SCL ReportControl validation rules."""
from __future__ import annotations


def _lname(tag):
    return tag.rsplit('}', 1)[-1]


def _children(e, name):
    return [c for c in list(e) if _lname(c.tag) == name]


def _desc(e, name):
    return [c for c in e.iter() if _lname(c.tag) == name]


def _ied_name(ld):
    try:
        return ld.server.access_point.ied.name or '<unnamed IED>'
    except Exception:
        return '<unknown IED>'


def _ln_id(ln):
    return getattr(ln, 'identifier', 'LN0')


def _datasets(ld):
    return _children(ld.element, 'DataSet')


def _run_dataset_checks(analyzer, ld, ln0, rc):
    ied = _ied_name(ld)
    name = rc.get('name') or '<unnamed>'
    loc = f'{_ln_id(ln0)}/ReportControl={name}'
    ds_name = rc.get('datSet')
    print(ied, name, loc, ds_name)
    if not ds_name:
        analyzer.add_issue('ERROR', 'REP-003', ied, loc, 'ReportControl is missing the datSet reference.')
        return
    matches = [d for d in _datasets(ln0) if d.get('name') == ds_name]
    if not matches:
        analyzer.add_issue('ERROR', 'REP-004', ied, loc, f"ReportControl references DataSet '{ds_name}', but it does not exist in the same LDevice.")
        return
    if len(matches) > 1:
        analyzer.add_issue('ERROR', 'REP-005', ied, loc, f"DataSet '{ds_name}' is duplicated in the same LDevice.")
        return
    fcdas = _children(matches[0], 'FCDA')
    if not fcdas:
        analyzer.add_issue('WARNING', 'REP-006', ied, loc, f"Referenced DataSet '{ds_name}' contains no FCDA entries.")
    for n, fcda in enumerate(fcdas, 1):
        if not fcda.get('doName'):
            analyzer.add_issue('ERROR', 'REP-007', ied, loc, f"DataSet '{ds_name}' FCDA #{n} has no doName.")


def _check_control(analyzer, ld, ln0, rc, seen):
    ied = _ied_name(ld)
    name = rc.get('name')
    loc = f'{_ln_id(ln0)}/ReportControl={name or "<unnamed>"}'
    if not name:
        analyzer.add_issue('ERROR', 'REP-001', ied, loc, 'ReportControl is missing the mandatory name attribute.')
    elif name in seen:
        analyzer.add_issue('ERROR', 'REP-002', ied, loc, f"Duplicate ReportControl name '{name}' within the same Logical Node.")
    else:
        seen.add(name)
    _run_dataset_checks(analyzer, ld, ln0, rc)

    buffered = rc.get('buffered')
    if buffered is not None and buffered.lower() not in ('true', 'false', '1', '0'):
        analyzer.add_issue('ERROR', 'REP-008', ied, loc, f"Invalid buffered value '{buffered}'.")

    for attr, rule in (('confRev', 'REP-009'), ('intgPd', 'REP-010')):
        value = rc.get(attr)
        if value is not None:
            try:
                if int(value) < 0:
                    raise ValueError
            except ValueError:
                analyzer.add_issue('ERROR', rule, ied, loc, f"Invalid {attr} value '{value}'.")

    trg = _children(rc, 'TrgOps')
    if not trg:
        analyzer.add_issue('WARNING', 'REP-TRG-001', ied, loc, 'ReportControl has no TrgOps element.')
    else:
        known = ('dchg', 'qchg', 'dupd', 'period', 'gi')
        if not any(trg[0].get(x) is not None for x in known):
            analyzer.add_issue('WARNING', 'REP-TRG-002', ied, loc, 'TrgOps contains no standard trigger attributes.')

    opt = _children(rc, 'OptFields')
    if not opt:
        analyzer.add_issue('WARNING', 'REP-OPT-001', ied, loc, 'ReportControl has no OptFields element.')

    enabled = _children(rc, 'RptEnabled')
    if not enabled:
        analyzer.add_issue('WARNING', 'REP-EN-001', ied, loc, 'ReportControl has no RptEnabled element.')
    for item in enabled:
        if item.get('max') is not None:
            try:
                if int(item.get('max')) < 0:
                    raise ValueError
            except ValueError:
                analyzer.add_issue('ERROR', 'REP-EN-002', ied, loc, f"RptEnabled has invalid max value '{item.get('max')}'.")


def run_report_rules(analyzer):
    """Validate ReportControl definitions without assuming reports are mandatory."""
    for ied in getattr(analyzer.model, 'ieds', []):
        for ap in getattr(ied, 'access_points', []):
            for server in getattr(ap, 'servers', []):
                for ld in getattr(server, 'l_devices', []):
                    ln0 = getattr(ld, 'ln0', None)
                    if ln0 is None:
                        continue
                    controls = _children(ln0.element, 'ReportControl')
                    seen = set()
                    for rc in controls:
                        _check_control(analyzer, ld, ln0, rc, seen)
