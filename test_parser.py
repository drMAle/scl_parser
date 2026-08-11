from scl_parser import SCLModel
import argparse

def main():

    parser = argparse.ArgumentParser(
        description="Test IEC 61850 SCL parser"
    )

    parser.add_argument(
        "scl_file",
        help="Path to the SCL file"
    )

    args = parser.parse_args()

    scl_file = args.scl_file

    print("=" * 60)
    print("SCL PARSER TEST")
    print("=" * 60)

    print()
    print(f"File: {scl_file}")

    model = SCLModel(scl_file)

    try:
        model.load()
    except Exception as exc:
        print()
        print("ERROR loading SCL:")
        print(exc)
        return

    print("=" * 60)
    print("SCL PARSER TEST")
    print("=" * 60)

    model = SCLModel(scl_file)

    try:
        model.load()
    except Exception as exc:
        print()
        print("ERROR loading SCL:")
        print(exc)
        return

    print()
    print("SCL loaded successfully.")
    print()

    # ---------------------------------------------------------
    # TYPE DEFINITIONS
    # ---------------------------------------------------------

    print("TYPE DEFINITIONS")
    print("-" * 60)

    print(f"LNodeTypes : {len(model.lnode_types)}")
    print(f"DOTypes    : {len(model.do_types)}")
    print(f"DATypes    : {len(model.da_types)}")
    print(f"EnumTypes  : {len(model.enum_types)}")

    # ---------------------------------------------------------
    # IEDS
    # ---------------------------------------------------------

    print()
    print("IEDs")
    print("-" * 60)

    for ied in model.ieds:

        print(f"IED: {ied.name}")

        for ap in ied.access_points:

            print(f"  AccessPoint: {ap.name}")

            for server in ap.servers:

                print(f"    Server: {server.name}")

                for ld in server.l_devices:

                    print(f"      LDevice: {ld.inst}")

                    for ln in ld.all_logical_nodes:

                        print(
                            f"        LN: "
                            f"{ln.prefix}"
                            f"{ln.ln_class}"
                            f"{ln.inst}"
                            f" "
                            f"(type={ln.ln_type})"
                        )

                        print(
                            f"          DOI: "
                            f"{', '.join(ln.get_data_object_names())}"
                        )

    # ---------------------------------------------------------
    # SEARCH TEST
    # ---------------------------------------------------------

    print()
    print("SEARCH TEST")
    print("-" * 60)

    for ied in model.ieds:

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    dgens = ld.find_logical_nodes(
                        ln_class="DGEN"
                    )

                    for ln in dgens:

                        print(
                            f"DGEN "
                            f"prefix={ln.prefix} "
                            f"inst={ln.inst} "
                            f"type={ln.ln_type}"
                        )

                        print(
                            f"  instantiated DOs: "
                            f"{ln.get_data_object_names()}"
                        )

                        print(
                            f"  defined DOs: "
                            f"{ln.get_defined_data_object_names()}"
                        )

                        print(
                            f"  Has Health: "
                            f"{ln.has_data_object('Health')}"
                        )

                        print(
                            f"  Has GnGrId: "
                            f"{ln.has_data_object('GnGrId')}"
                        )

                        print()

    # ---------------------------------------------------------
    # NESTED SDI TEST
    # ---------------------------------------------------------

    print("SDI / DAI TEST")
    print("-" * 60)

    for ied in model.ieds:

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    for ln in ld.all_logical_nodes:

                        if ln.ln_class != "DWMX":
                            continue

                        do = ln.get_data_object(
                            "WMaxSptPct"
                        )

                        if do is None:
                            print(
                                "WMaxSptPct not instantiated"
                            )
                            continue

                        print(
                            "Found DWMX.WMaxSptPct"
                        )

                        mxval = do.get_sub_data_object(
                            "mxVal"
                        )

                        if mxval is None:
                            print(
                                "  ERROR: mxVal not found"
                            )
                            continue

                        print(
                            "  Found WMaxSptPct.mxVal"
                        )

                        f = mxval.get_data_attribute(
                            "f"
                        )

                        if f is None:
                            print(
                                "  ERROR: f not found"
                            )
                            continue

                        print(
                            f"  WMaxSptPct.mxVal.f = "
                            f"{f.value}"
                        )

    # ---------------------------------------------------------
    # FINISHED
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()