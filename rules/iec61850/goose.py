"""IEC 61850 SCL GOOSE/GSEControl validation rules."""
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


def _comm_gse(model, ld, cb_name):
    root = getattr(model, 'root', None)
    if root is None:
        return []
    out = []
    for gse in _desc(root, 'GSE'):
        if gse.get('cbName') != cb_name:
            continue
        if gse.get('ldInst') and ld.inst and gse.get('ldInst') != ld.inst:
            continue
        out.append(gse)
    return out


def _address_values(gse):
    out = {}
    for address in _children(gse, 'Address'):
        for p in _children(address, 'P'):
            if p.get('type'):
                out[p.get('type')] = (p.text or '').strip()
    return out


def _check(analyzer, model, ld, ln0, gcb, seen):
    ied = _ied_name(ld)
    name = gcb.get('name')
    loc = f'{_ln_id(ln0)}/GSEControl={name or "<unnamed>"}'
    if not name:
        analyzer.add_issue('ERROR', 'GOOSE-001', ied, loc, 'GSEControl is missing the mandatory name attribute.')
    elif name in seen:
        analyzer.add_issue('ERROR', 'GOOSE-002', ied, loc, f"Duplicate GSEControl name '{name}' within the same Logical Node.")
    else:
        seen.add(name)

    typ = gcb.get('type')
    if typ and typ.upper() != 'GOOSE':
        analyzer.add_issue('ERROR', 'GOOSE-003', ied, loc, f"GSEControl '{name}' has invalid type '{typ}'; expected 'GOOSE'.")

    ds_name = gcb.get('datSet')
    if not ds_name:
        analyzer.add_issue('ERROR', 'GOOSE-004', ied, loc, 'GSEControl is missing the datSet reference.')
    else:
        ds = [d for d in _children(ld.element, 'DataSet') if d.get('name') == ds_name]
        if not ds:
            analyzer.add_issue('ERROR', 'GOOSE-005', ied, loc, f"GSEControl references DataSet '{ds_name}', but it does not exist in the same LDevice.")
        elif len(ds) > 1:
            analyzer.add_issue('ERROR', 'GOOSE-006', ied, loc, f"DataSet '{ds_name}' is duplicated in the same LDevice.")
        else:
            fcdas = _children(ds[0], 'FCDA')
            if not fcdas:
                analyzer.add_issue('WARNING', 'GOOSE-007', ied, loc, f"Referenced DataSet '{ds_name}' contains no FCDA entries.")
            for n, fcda in enumerate(fcdas, 1):
                if not fcda.get('doName'):
                    analyzer.add_issue('ERROR', 'GOOSE-008', ied, loc, f"DataSet '{ds_name}' FCDA #{n} has no doName.")

    if gcb.get('confRev') is not None:
        try:
            if int(gcb.get('confRev')) < 0:
                raise ValueError
        except ValueError:
            analyzer.add_issue('ERROR', 'GOOSE-012', ied, loc, f"GSEControl has invalid confRev '{gcb.get('confRev')}'.")

    bindings = _comm_gse(model, ld, name)
    if not bindings:
        analyzer.add_issue('WARNING', 'GOOSE-013', ied, loc, 'No Communication/GSE binding was found for this GSEControl.')
        return
    if len(bindings) > 1:
        analyzer.add_issue('WARNING', 'GOOSE-014', ied, loc, f"Multiple Communication/GSE bindings found for GSEControl '{name}'.")
    for gse in bindings:
        addresses = _address_values(gse)
        if not _children(gse, 'Address'):
            analyzer.add_issue('WARNING', 'GOOSE-009', ied, loc, 'Communication GSE has no Address element.')
            continue
        for ptype in ('MAC-Address', 'APPID'):
            if not addresses.get(ptype):
                analyzer.add_issue('WARNING', 'GOOSE-010', ied, loc, f"Communication GSE Address is missing P type '{ptype}'.")


def run_goose_rules(analyzer):
    """Validate GSEControl -> DataSet -> FCDA and Communication GSE bindings."""
    for ied in getattr(analyzer.model, 'ieds', []):
        for ap in getattr(ied, 'access_points', []):
            for server in getattr(ap, 'servers', []):
                for ld in getattr(server, 'l_devices', []):
                    ln0 = getattr(ld, 'ln0', None)
                    if ln0 is None:
                        continue
                    seen = set()
                    for gcb in _children(ln0.element, 'GSEControl'):
                        _check(analyzer, analyzer.model, ld, ln0, gcb, seen)
