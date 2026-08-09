import xml.etree.ElementTree as ET


def local_name(tag):
    """
    Returns the XML local name, ignoring the namespace.
    Example:
        {http://www.iec.ch/61850/2003/SCL}IED -> IED
    """
    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


def children(element, name):
    """
    Returns direct children having the specified local name.
    """
    return [
        child
        for child in list(element)
        if local_name(child.tag) == name
    ]


def descendants(element, name):
    """
    Returns all descendants having the specified local name.
    """
    return [
        child
        for child in element.iter()
        if local_name(child.tag) == name
    ]


class SCLModel:

    def __init__(self, filename):
        self.filename = filename
        self.tree = None
        self.root = None

        self.ieds = []

    def load(self):
        self.tree = ET.parse(self.filename)
        self.root = self.tree.getroot()

        self._parse_ieds()

    def _parse_ieds(self):

        self.ieds = []

        for element in descendants(self.root, "IED"):
            ied = IED(
                element,
                self
            )

            self.ieds.append(ied)


class IED:

    def __init__(self, element, model):

        self.element = element
        self.model = model

        self.name = element.get("name")
        self.ied_type = element.get("type")

        self.access_points = []

        for element_ap in children(
            element,
            "AccessPoint"
        ):

            self.access_points.append(
                AccessPoint(
                    element_ap,
                    self
                )
            )


class AccessPoint:

    def __init__(self, element, ied):

        self.element = element
        self.ied = ied

        self.name = element.get("name")

        self.servers = []

        for element_server in children(
            element,
            "Server"
        ):

            self.servers.append(
                Server(
                    element_server,
                    self
                )
            )


class Server:

    def __init__(self, element, access_point):

        self.element = element
        self.access_point = access_point

        self.l_devices = []

        for element_ld in children(
            element,
            "LDevice"
        ):

            self.l_devices.append(
                LDevice(
                    element_ld,
                    self
                )
            )


class LDevice:

    def __init__(self, element, server):

        self.element = element
        self.server = server

        self.inst = element.get("inst")

        self.logical_nodes = []
        self.ln0 = None

        for element_ln in children(
            element,
            "LN0"
        ):

            if self.ln0 is None:
                self.ln0 = LogicalNode(
                    element_ln,
                    self,
                    is_ln0=True
                )

        for element_ln in children(
            element,
            "LN"
        ):

            self.logical_nodes.append(
                LogicalNode(
                    element_ln,
                    self,
                    is_ln0=False
                )
            )


class LogicalNode:

    def __init__(
        self,
        element,
        l_device,
        is_ln0=False
    ):

        self.element = element
        self.l_device = l_device
        self.is_ln0 = is_ln0

        self.ln_class = element.get("lnClass")
        self.inst = element.get("inst")
        self.prefix = element.get("prefix", "")

        self.data_objects = []

        for do in children(
            element,
            "DOI"
        ):

            self.data_objects.append(do)


def find_all(element, name):
    """
    Generic helper used by rules.
    """
    return descendants(element, name)


def find_direct(element, name):
    """
    Generic helper for direct children.
    """
    return children(element, name)
