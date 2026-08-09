"""
CEI 0-16 specific SCL validation rules.

This module currently checks the presence of:
    - the mandatory Logical Device LD_Plant
    - mandatory Logical Nodes
    - mandatory Data Objects
    - mandatory Data Attributes

It does not yet validate:
    - attribute values
    - control models
    - functional constraints
    - reporting intervals
    - GOOSE configuration
    - communication parameters
"""


# =============================================================
# CEI 0-16 REQUIREMENTS
# =============================================================

CEI_REQUIREMENTS = {

    "LLN0": {
        "dos":{} 
    },

    "LPHD": {
        "dos": {
            "PhyNam": [
                "vendor",
                "swRev",
                "location",
            ]
        }
    },

    "DPCC": {
        "dos": {
            "WRtg": [
                "setMag",
            ],
            "VArRtg": [
                "setMag",
            ],
            "VARtg": [
                "setMag",
            ],
        }
    },

    "DECP": {
        "dos": {
            "Beh": [
                "stVal",
            ]
        }
    },

    "DGEN": {
        "dos": {
            "Beh": [
                "stVal",
            ],
            "Health": [
                "stVal",
            ],
            "GnGrId": []
        }
    },

    "DSTO": {
        "dos": {
            "Beh": [
                "stVal",
            ]
        }
    },

    "XCBR": {
        "dos": {
            "Pos": [
                "stVal",
            ]
        }
    },

    "MMXU": {
        "dos": {
            "TotW": [
                "mag",
            ],
            "TotVAr": [
                "mag",
            ],
            "PPV": [
                "mag",
            ],
            # A is explicitly optional
        }
    },

    "DWMX": {
        "dos": {
            "Beh": [],
            "Health": [],
            "WMaxSptPct": [],
            "Mod": [],
            "FctOpStAuto": [],
            "FctOpStEx": [],
        }
    },

    "DAGC": {
        "dos": {
            "Beh": [],
            "Health": [],
            "WSptPct": [],
            "Mod": [],
            "FctOpSt": [],
        }
    },

    "DVAR": {
        "dos": {
            "Beh": [],
            "Health": [],
            "VArTgtSptPct": [],
            "Mod": [],
            "FctOpSt": [],
        }
    },

    "DFPF": {
        "dos": {
            "Beh": [],
            "Health": [],
            "PFGnTgtSpt": [],
            "PFLodTgtSpt": [],
            "Mod": [],
            "FctOpSt": [],
        }
    },

    "DVVR": {
        "dos": {
            "Beh": [],
            "Health": [],
            "Mod": [],
            "FctOpSt": [],
            "K": [
                "setMag",
            ],
        }
    },

    "DPMC": {
        "dos": {
            "WSpt1": [
                "ctlVal",
            ]
        }
    },

    "DPFW": {
        "dos": {
            "Beh": [],
            "Health": [],
            "Mod": [],
            "FctOpSt": [],

            "WSetA": [],
            "PFSetA": [],

            "WSetB": [],
            "PFSetB": [],

            "WSetC": [],
            "PFSetC": [],

            "VLkIn": [],
            "VLkOut": [],
        }
    },
}


# =============================================================
# XML HELPERS
# =============================================================

def local_name(tag):
    """
    Return XML local name, ignoring namespace.
    """
    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


def get_direct_children(element, name):
    """
    Return direct children with the specified local name.
    """
    return [
        child
        for child in list(element)
        if local_name(child.tag) == name
    ]


def get_do_map(ln_element):
    """
    Return a dictionary:

        DO name -> DOI XML element

    Only direct DOI children of the LN are considered.
    """

    result = {}

    for doi in get_direct_children(
        ln_element,
        "DOI"
    ):

        name = doi.get("name")

        if name:
            result[name] = doi

    return result


def get_da_map(doi_element):
    """
    Return a dictionary:

        DA name -> DAI XML element

    Only direct DAI children of the DOI are considered.
    """

    result = {}

    for dai in get_direct_children(
        doi_element,
        "DAI"
    ):

        name = dai.get("name")

        if name:
            result[name] = dai

    return result


# =============================================================
# MAIN CEI 0-16 RULE
# =============================================================

def run_cei016_rules(analyzer):

    model = analyzer.model

    # ---------------------------------------------------------
    # CEI-LD-001
    #
    # CEI 0-16 model must be contained in LD_Plant.
    # ---------------------------------------------------------

    plant_devices = []

    for ied in model.ieds:

        for ap in ied.access_points:

            for server in ap.servers:

                for ld in server.l_devices:

                    if ld.inst == "LD_Plant":
                        plant_devices.append(
                            (ied, ap, server, ld)
                        )

    if not plant_devices:

        analyzer.add_issue(
            "ERROR",
            "CEI-LD-001",
            "",
            "LD_Plant",
            "Mandatory Logical Device 'LD_Plant' was not found."
        )

        # There is no meaningful way to continue the
        # CEI-specific LN/DO checks.
        return

    # ---------------------------------------------------------
    # If more than one LD_Plant exists, report it.
    # ---------------------------------------------------------

    if len(plant_devices) > 1:

        analyzer.add_issue(
            "ERROR",
            "CEI-LD-002",
            "",
            "LD_Plant",
            "More than one Logical Device named 'LD_Plant' was found."
        )

    # ---------------------------------------------------------
    # Analyze every LD_Plant found.
    #
    # We deliberately continue here, so all errors are shown
    # in one analysis rather than stopping at the first error.
    # ---------------------------------------------------------

    for ied, ap, server, ld in plant_devices:

        ied_name = ied.name or "<unnamed>"

        check_required_lns(
            analyzer,
            ied_name,
            ld
        )


# =============================================================
# LOGICAL NODE CHECKS
# =============================================================

def check_required_lns(
    analyzer,
    ied_name,
    ld
):

    # ---------------------------------------------------------
    # Build map of Logical Nodes.
    #
    # LN0 is represented separately by the parser.
    # ---------------------------------------------------------

    ln_map = {}

    if ld.ln0 is not None:

        ln_class = (
            ld.ln0.ln_class
            or "LLN0"
        )

        ln_map[ln_class] = ld.ln0

    for ln in ld.logical_nodes:

        if ln.ln_class:

            ln_map[ln.ln_class] = ln

    # ---------------------------------------------------------
    # Required Logical Nodes
    # ---------------------------------------------------------

    for ln_class, requirement in CEI_REQUIREMENTS.items():

        if ln_class not in ln_map:

            analyzer.add_issue(
                "ERROR",
                "CEI-LN-001",
                ied_name,
                f"LD_Plant/LN={ln_class}",
                f"Mandatory Logical Node '{ln_class}' "
                f"was not found in LD_Plant."
            )

            continue

        ln = ln_map[ln_class]

        check_required_dos(
            analyzer,
            ied_name,
            ln_class,
            ln,
            requirement
        )


# =============================================================
# DATA OBJECT CHECKS
# =============================================================

def check_required_dos(
    analyzer,
    ied_name,
    ln_class,
    ln,
    requirement
):

    if "dos" not in requirement:
        return

    required_dos = requirement["dos"]

    do_map = get_do_map(
        ln.element
    )

    for do_name, required_das in required_dos.items():

        # -----------------------------------------------------
        # Mandatory DO
        # -----------------------------------------------------

        if do_name not in do_map:

            analyzer.add_issue(
                "ERROR",
                "CEI-DO-001",
                ied_name,
                f"LD_Plant/{ln_class}/{do_name}",
                f"Mandatory Data Object '{do_name}' "
                f"is missing from Logical Node '{ln_class}'."
            )

            continue

        doi = do_map[do_name]

        # -----------------------------------------------------
        # Mandatory DA
        # -----------------------------------------------------

        if required_das:

            da_map = get_da_map(
                doi
            )

            for da_name in required_das:

                if da_name not in da_map:

                    analyzer.add_issue(
                        "ERROR",
                        "CEI-DA-001",
                        ied_name,
                        (
                            f"LD_Plant/"
                            f"{ln_class}/"
                            f"{do_name}/"
                            f"{da_name}"
                        ),
                        f"Mandatory Data Attribute '{da_name}' "
                        f"is missing from Data Object "
                        f"'{do_name}' in Logical Node "
                        f"'{ln_class}'."
                    )
