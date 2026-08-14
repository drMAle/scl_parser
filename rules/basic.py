from model import local_name


def _issue(analyzer, sev, rule, ied, loc, msg):
    analyzer.add_issue(sev, rule, ied, loc, msg)


def run_basic_rules(analyzer):
    model = analyzer.model
    ieds = getattr(model, 'ieds', [])
    if not ieds:
        _issue(analyzer, 'ERROR', 'SCL-001', '', 'SCL', 'SCL file contains no IED.')
        return
    names = set()
    for ied in ieds:
        name = ied.name or ''
        if not name:
            _issue(analyzer, 'ERROR', 'IED-001', '', 'IED', 'IED name is missing.')
        elif name in names:
            _issue(analyzer, 'ERROR', 'IED-002', name, f'IED={name}', 'Duplicate IED name.')
        names.add(name)
        if not ied.access_points:
            _issue(analyzer, 'ERROR', 'IED-003', name, f'IED={name}', 'IED contains no AccessPoint.')
        for ap in ied.access_points:
            if not ap.servers:
                _issue(analyzer, 'ERROR', 'AP-001', name, f'IED={name}/AP={ap.name}', 'AccessPoint contains no Server.')
            for server in ap.servers:
                for ld in server.l_devices:
                    loc=f'IED={name}/AP={ap.name}/Server={server.name}/LDevice={ld.name or ld.inst}'
                    if not ld.inst:
                        _issue(analyzer,'ERROR','LD-001',name,loc,'LDevice.inst is missing.')
                    if ld.ln0 is None:
                        _issue(analyzer,'ERROR','LD-002',name,loc,'LDevice contains no LN0.')
                    seen=set()
                    for ln in ld.all_logical_nodes:
                        if not ln.ln_class:
                            _issue(analyzer,'ERROR','LN-001',name,loc,'Logical Node lnClass is missing.')
                        if not ln.inst and not ln.is_ln0:
                            _issue(analyzer,'ERROR','LN-002',name,loc,f'Logical Node {ln.identifier} has no inst.')
                        key=(ln.ln_class,ln.prefix,ln.inst,ln.is_ln0)
                        if key in seen:
                            _issue(analyzer,'ERROR','LN-003',name,loc,f'Duplicate Logical Node {ln.identifier}.')
                        seen.add(key)
