from model import descendants


def _controls(ld, tag):
    return [e for e in descendants(ld.element, tag)]


def _datasets(ld):
    return {e.get('name') for e in descendants(ld.element,'DataSet') if e.get('name')}


def run_report_rules(analyzer):
    for ied in analyzer.model.ieds:
        name=ied.name or ''
        for ap in ied.access_points:
            for server in ap.servers:
                for ld in server.l_devices:
                    loc=f'IED={name}/AP={ap.name}/Server={server.name}/LDevice={ld.name or ld.inst}'
                    datasets=_datasets(ld)
                    for rc in _controls(ld,'ReportControl'):
                        n=rc.get('name')
                        if not n:
                            analyzer.add_issue('ERROR','REP-001',name,loc,'ReportControl name is missing.')
                        ds=rc.get('datSet')
                        if not ds:
                            analyzer.add_issue('ERROR','REP-002',name,loc,f"ReportControl '{n or '<unnamed>'}' has no datSet reference.")
                        elif ds not in datasets:
                            analyzer.add_issue('ERROR','REP-003',name,loc,f"ReportControl '{n}' references missing DataSet '{ds}'.")
