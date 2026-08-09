from scl_parser import find_all


def run_report_rules(analyzer):

    model = analyzer.model

    for ied in model.ieds:

        ied_name = ied.name or "<unnamed>"

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    if ld.ln0 is not None:

                        check_reports(
                            analyzer,
                            ld.ln0.element,
                            ied_name,
                            ld.inst,
                            "LN0"
                        )

                    for ln in ld.logical_nodes:

                        check_reports(
                            analyzer,
                            ln.element,
                            ied_name,
                            ld.inst,
                            f"{ln.ln_class}[{ln.inst}]"
                        )


def check_reports(
    analyzer,
    element,
    ied_name,
    ld_inst,
    ln_name
):

    datasets = {}

    for ds in find_all(element, "DataSet"):

        name = ds.get("name")

        if name:
            datasets[name] = ds

    for rc in find_all(element, "ReportControl"):

        name = rc.get("name")

        location = (
            f"IED={ied_name}/"
            f"LDevice={ld_inst}/"
            f"{ln_name}/"
            f"ReportControl={name}"
        )

        # RC-001
        if not name:

            analyzer.add_issue(
                "ERROR",
                "RC-001",
                ied_name,
                location,
                "ReportControl has no 'name' attribute."
            )

        dataset_name = rc.get("datSet")

        if dataset_name:

            # RC-002
            if dataset_name not in datasets:

                analyzer.add_issue(
                    "ERROR",
                    "RC-002",
                    ied_name,
                    location,
                    f"ReportControl references "
                    f"unknown DataSet '{dataset_name}'."
                )

        else:

            analyzer.add_issue(
                "WARNING",
                "RC-002",
                ied_name,
                location,
                "ReportControl has no 'datSet' attribute."
            )
