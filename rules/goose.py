from model import descendants


def run_goose_rules(analyzer):
    for ied in analyzer.model.ieds:
        name=ied.name or ''
        for ap in ied.access_points:
            for server in ap.servers:
                for ld in server.l_devices:
                    loc=f'IED={name}/AP={ap.name}/Server={server.name}/LDevice={ld.name or ld.inst}'
                    datasets={e.get('name') for e in descendants(ld.element,'DataSet') if e.get('name')}
                    for gc in descendants(ld.element,'GSEControl'):
                        n=gc.get('name')
                        if not n:
                            analyzer.add_issue('ERROR','GOOSE-001',name,loc,'GSEControl name is missing.')
                        ds=gc.get('datSet')
                        if not ds:
                            analyzer.add_issue('ERROR','GOOSE-002',name,loc,f"GSEControl '{n or '<unnamed>'}' has no datSet reference.")
                        elif ds not in datasets:
                            analyzer.add_issue('ERROR','GOOSE-003',name,loc,f"GSEControl '{n}' references missing DataSet '{ds}'.")
