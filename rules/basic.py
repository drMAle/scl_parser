def run_basic_rules(analyzer):

    model = analyzer.model

    # ---------------------------------------------------------
    # SCL-002
    # ---------------------------------------------------------

    if not model.ieds:

        analyzer.add_issue(
            "ERROR",
            "SCL-002",
            "",
            "SCL",
            "No IED element found."
        )

        return

    # ---------------------------------------------------------
    # IED rules
    # ---------------------------------------------------------

    names = {}

    for ied in model.ieds:

        name = ied.name or ""

        # IED-001
        if not name:

            analyzer.add_issue(
                "ERROR",
                "IED-001",
                "<unnamed>",
                "IED",
                "IED has no 'name' attribute."
            )

        # IED-002
        else:

            if name in names:

                analyzer.add_issue(
                    "ERROR",
                    "IED-002",
                    name,
                    "IED",
                    f"IED name '{name}' is duplicated."
                )

            else:
                names[name] = ied

        # IED-003
        if not ied.access_points:

            analyzer.add_issue(
                "ERROR",
                "IED-003",
                name,
                "IED",
                "IED has no AccessPoint."
            )

        # -----------------------------------------------------
        # Access Points
        # -----------------------------------------------------

        for ap in ied.access_points:

            if not ap.servers:

                analyzer.add_issue(
                    "ERROR",
                    "AP-001",
                    name,
                    f"AccessPoint/{ap.name}",
                    "AccessPoint has no Server."
                )

            # -------------------------------------------------
            # Servers
            # -------------------------------------------------

            for server in ap.servers:

                for ld in server.l_devices:

                    location = (
                        f"IED={name}/"
                        f"AP={ap.name}/"
                        f"LDevice={ld.inst}"
                    )

                    # LD-001
                    if not ld.inst:

                        analyzer.add_issue(
                            "ERROR",
                            "LD-001",
                            name,
                            location,
                            "LDevice has no 'inst' attribute."
                        )

                    # LD-002
                    if ld.ln0 is None:

                        analyzer.add_issue(
                            "ERROR",
                            "LD-002",
                            name,
                            location,
                            "LDevice has no LN0."
                        )

                    # -------------------------------------------------
                    # LN0
                    # -------------------------------------------------

                    if ld.ln0 is not None:

                        ln0 = ld.ln0

                        if not ln0.ln_class:

                            analyzer.add_issue(
                                "ERROR",
                                "LN-001",
                                name,
                                location + "/LN0",
                                "LN0 has no 'lnClass' attribute."
                            )

                    # -------------------------------------------------
                    # Logical Nodes
                    # -------------------------------------------------

                    ln_keys = set()

                    for ln in ld.logical_nodes:

                        ln_location = (
                            location +
                            f"/LN={ln.ln_class}"
                            f"[{ln.inst}]"
                        )

                        # LN-001
                        if not ln.ln_class:

                            analyzer.add_issue(
                                "ERROR",
                                "LN-001",
                                name,
                                ln_location,
                                "Logical Node has no 'lnClass' attribute."
                            )

                        # LN-002
                        if not ln.inst:

                            analyzer.add_issue(
                                "ERROR",
                                "LN-002",
                                name,
                                ln_location,
                                "Logical Node has no 'inst' attribute."
                            )

                        # LN-003
                        key = (
                            ln.prefix,
                            ln.ln_class,
                            ln.inst
                        )

                        if key in ln_keys:

                            analyzer.add_issue(
                                "ERROR",
                                "LN-003",
                                name,
                                ln_location,
                                "Duplicate Logical Node in the same LDevice."
                            )

                        else:

                            ln_keys.add(key)
