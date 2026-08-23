from model import descendants, local_name


def run_dataset_rules(analyzer):
    for ied in analyzer.model.ieds:
        name=ied.name or ''
        for ap in ied.access_points:
            for server in ap.servers:
                for ld in server.l_devices:
                    loc=f'IED={name}/AP={ap.name}/Server={server.name}/LDevice={ld.name or ld.inst}'
                    datasets=[e for e in descendants(ld.element,'DataSet')]
                    seen=set()
                    for ds in datasets:
                        n=ds.get('name')
                        if not n:
                            analyzer.add_issue('ERROR','DS-001',name,loc,'DataSet name is missing.')
                        elif n in seen:
                            analyzer.add_issue('ERROR','DS-002',name,loc,f"Duplicate DataSet name '{n}'.")
                        seen.add(n)
                        for fcda in [e for e in descendants(ds,'FCDA')]:
                            for attr, rule in [('ldInst','DS-003'),('lnClass','DS-004'),('lnInst','DS-005'),('doName','DS-006')]:
                                if not fcda.get(attr):
                                    analyzer.add_issue('ERROR',rule,name,loc,f"FCDA is missing required attribute '{attr}'.")
