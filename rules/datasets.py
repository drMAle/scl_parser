from scl_parser import find_all


def run_dataset_rules(analyzer):

    model = analyzer.model

    for ied in model.ieds:

        ied_name = ied.name or "<unnamed>"

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    if ld.ln0 is not None:

                        check_datasets(
                            analyzer,
                            ld.ln0.element,
                            ied_name,
                            ld.inst,
                            "LN0"
                        )

                    for ln in ld.logical_nodes:

                        check_datasets(
                            analyzer,
                            ln.element,
                            ied_name,
                            ld.inst,
                            f"{ln.ln_class}[{ln.inst}]"
                        )


def check_datasets(
    analyzer,
    element,
    ied_name,
    ld_inst,
    ln_name
):

    datasets = [
        x
        for x in list(element)
        if x.tag.endswith("DataSet")
    ]

    dataset_names = set()

    # ---------------------------------------------------------
    # DataSet checks
    # ---------------------------------------------------------

    for dataset in datasets:

        name = dataset.get("name")

        location = (
            f"IED={ied_name}/"
            f"LDevice={ld_inst}/"
            f"{ln_name}/"
            f"DataSet={name}"
        )

        # DS-001
        if not name:

            analyzer.add_issue(
                "ERROR",
                "DS-001",
                ied_name,
                location,
                "DataSet has no 'name' attribute."
            )

        elif name in dataset_names:

            analyzer.add_issue(
                "ERROR",
                "DS-001",
                ied_name,
                location,
                f"Duplicate DataSet name '{name}'."
            )

        else:

            dataset_names.add(name)

        # -----------------------------------------------------
        # FCDA
        # -----------------------------------------------------

        for fcda in find_all(dataset, "FCDA"):

            fcda_location = (
                location +
                "/FCDA"
            )

            # DS-002
            if not fcda.get("ldInst"):

                analyzer.add_issue(
                    "WARNING",
                    "DS-002",
                    ied_name,
                    fcda_location,
                    "FCDA has no 'ldInst' attribute."
                )

            # DS-003
            if not fcda.get("lnClass"):

                analyzer.add_issue(
                    "WARNING",
                    "DS-003",
                    ied_name,
                    fcda_location,
                    "FCDA has no 'lnClass' attribute."
                )

            # DS-004
            if not fcda.get("lnInst"):

                analyzer.add_issue(
                    "WARNING",
                    "DS-004",
                    ied_name,
                    fcda_location,
                    "FCDA has no 'lnInst' attribute."
                )

            # DS-005
            if not fcda.get("doName"):

                analyzer.add_issue(
                    "WARNING",
                    "DS-005",
                    ied_name,
                    fcda_location,
                    "FCDA has no 'doName' attribute."
                )
