from scl_parser import find_all


def run_goose_rules(analyzer):

    model = analyzer.model

    for ied in model.ieds:

        ied_name = ied.name or "<unnamed>"

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    if ld.ln0 is None:
                        continue

                    element = ld.ln0.element

                    datasets = {}

                    for ds in find_all(
                        element,
                        "DataSet"
                    ):

                        name = ds.get("name")

                        if name:
                            datasets[name] = ds

                    for gse in find_all(
                        element,
                        "GSEControl"
                    ):

                        name = gse.get("name")

                        location = (
                            f"IED={ied_name}/"
                            f"LDevice={ld.inst}/"
                            f"LN0/"
                            f"GSEControl={name}"
                        )

                        # GSE-001
                        if not name:

                            analyzer.add_issue(
                                "ERROR",
                                "GSE-001",
                                ied_name,
                                location,
                                "GSEControl has no 'name' attribute."
                            )

                        dataset_name = gse.get("datSet")

                        # GSE-002
                        if dataset_name:

                            if dataset_name not in datasets:

                                analyzer.add_issue(
                                    "ERROR",
                                    "GSE-002",
                                    ied_name,
                                    location,
                                    f"GSEControl references "
                                    f"unknown DataSet '{dataset_name}'."
                                )

                        else:

                            analyzer.add_issue(
                                "WARNING",
                                "GSE-002",
                                ied_name,
                                location,
                                "GSEControl has no 'datSet' attribute."
                            )
