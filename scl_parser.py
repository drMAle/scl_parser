
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


class SCLModel:
    """
    In-memory representation of an IEC 61850 SCL file.

    The model preserves the original XML elements while providing
    convenient Python objects for:

        SCL
          IED
            AccessPoint
              Server
                LDevice
                  LN0 / LN
                    DOI
                      DAI / SDI

    It also indexes the SCL type system:

        LNodeType
        DOType
        DAType
        EnumType

    and resolves LNodeType inheritance where the SCL contains
    a base/baseType/baseTypeId reference.
    """

    def __init__(self, filename):
        self.filename = filename

        self.tree = None
        self.root = None

        self.ieds = []

        # IEC 61850 type definitions
        self.lnode_types = {}
        self.do_types = {}
        self.da_types = {}
        self.enum_types = {}

    def load(self):
        """
        Parse the SCL file and build the object model.
        """
        self.tree = ET.parse(self.filename)
        self.root = self.tree.getroot()

        self._parse_type_definitions()
        self._parse_ieds()

    # ------------------------------------------------------------------
    # TYPE DEFINITIONS
    # ------------------------------------------------------------------

    def _parse_type_definitions(self):
        """
        Index all IEC 61850 type definitions found in the SCL file.
        """
        self.lnode_types = {}
        self.do_types = {}
        self.da_types = {}
        self.enum_types = {}

        for element in descendants(self.root, "LNodeType"):
            type_id = element.get("id")

            if type_id:
                self.lnode_types[type_id] = element

        for element in descendants(self.root, "DOType"):
            type_id = element.get("id")

            if type_id:
                self.do_types[type_id] = element

        for element in descendants(self.root, "DAType"):
            type_id = element.get("id")

            if type_id:
                self.da_types[type_id] = element

        for element in descendants(self.root, "EnumType"):
            type_id = element.get("id")

            if type_id:
                self.enum_types[type_id] = element

    def get_lnode_type(self, type_id):
        """
        Return the raw LNodeType XML element.
        """
        return self.lnode_types.get(type_id)

    def get_do_type(self, type_id):
        """
        Return the raw DOType XML element.
        """
        return self.do_types.get(type_id)

    def get_da_type(self, type_id):
        """
        Return the raw DAType XML element.
        """
        return self.da_types.get(type_id)

    def get_enum_type(self, type_id):
        """
        Return the raw EnumType XML element.
        """
        return self.enum_types.get(type_id)

    def _get_lnode_type_base(self, element):
        """
        Return the base LNodeType reference.

        SCL files encountered in the field may use different attribute
        names. The standard SCL representation normally uses 'base',
        but the parser accepts the common variants as well.
        """
        if element is None:
            return None

        return (
            element.get("base")
            or element.get("baseType")
            or element.get("baseTypeId")
        )

    def resolve_lnode_type(self, type_id, visited=None):
        """
        Resolve an LNodeType into a dictionary of DO definitions.

        Parent types are resolved first. If a derived LNodeType defines
        a DO with the same name, the derived definition overrides it.

        Returns:
            dict[str, xml.etree.ElementTree.Element]
        """
        if visited is None:
            visited = set()

        if not type_id:
            return {}

        if type_id in visited:
            raise ValueError(
                "Circular LNodeType inheritance detected: "
                + type_id
            )

        element = self.lnode_types.get(type_id)

        if element is None:
            return {}

        current_visited = set(visited)
        current_visited.add(type_id)

        result = {}

        base_type = self._get_lnode_type_base(element)

        if base_type:
            result.update(
                self.resolve_lnode_type(
                    base_type,
                    current_visited
                )
            )

        for do in children(element, "DO"):
            name = do.get("name")

            if name:
                result[name] = do

        return result

    # ------------------------------------------------------------------
    # IED PARSING
    # ------------------------------------------------------------------

    def _parse_ieds(self):
        self.ieds = []

        for element in descendants(self.root, "IED"):
            self.ieds.append(
                IED(
                    element,
                    self
                )
            )

    # ------------------------------------------------------------------
    # CONVENIENCE METHODS
    # ------------------------------------------------------------------

    def get_ied(self, name):
        """
        Return the IED with the specified name, or None.
        """
        for ied in self.ieds:
            if ied.name == name:
                return ied

        return None


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

    def get_access_point(self, name):
        for access_point in self.access_points:
            if access_point.name == name:
                return access_point

        return None


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

    def get_server(self, name=None):
        if name is None:
            return self.servers[0] if self.servers else None

        for server in self.servers:
            if server.name == name:
                return server

        return None


class Server:

    def __init__(self, element, access_point):

        self.element = element
        self.access_point = access_point

        self.name = element.get("name")

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

    def get_l_device(self, inst=None, name=None):
        for l_device in self.l_devices:
            if inst is not None and l_device.inst == inst:
                return l_device

            if name is not None and l_device.name == name:
                return l_device

        return None


class LDevice:

    def __init__(self, element, server):

        self.element = element
        self.server = server

        self.inst = element.get("inst")
        self.name = element.get("name")

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

    @property
    def all_logical_nodes(self):
        """
        Return LN0 followed by normal logical nodes.
        """
        result = []

        if self.ln0 is not None:
            result.append(self.ln0)

        result.extend(self.logical_nodes)

        return result

    def find_logical_nodes(
        self,
        ln_class=None,
        prefix=None,
        inst=None
    ):
        """
        Find logical nodes using optional filters.
        """
        result = []

        for ln in self.all_logical_nodes:

            if ln_class is not None:
                if ln.ln_class != ln_class:
                    continue

            if prefix is not None:
                if ln.prefix != prefix:
                    continue

            if inst is not None:
                if ln.inst != inst:
                    continue

            result.append(ln)

        return result


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
        self.ln_type = element.get("lnType")

        self.data_objects = []

        for doi_element in children(
            element,
            "DOI"
        ):
            self.data_objects.append(
                DataObject(
                    doi_element,
                    self,
                    inherited=False
                )
            )

        # Complete DO model resolved from the LNodeType.
        self.type_data_objects = {}

        if self.ln_type:
            self.type_data_objects = (
                self.l_device
                .server
                .access_point
                .ied
                .model
                .resolve_lnode_type(
                    self.ln_type
                )
            )

    @property
    def model(self):
        return self.l_device.server.access_point.ied.model

    @property
    def identifier(self):
        """
        Human-readable LN identifier.
        """
        return (
            f"{self.prefix}"
            f"{self.ln_class or ''}"
            f"{self.inst or ''}"
        )

    def get_data_object(self, name):
        """
        Return the instantiated DOI with the specified name.
        """
        for data_object in self.data_objects:
            if data_object.name == name:
                return data_object

        return None

    def get_defined_data_object(self, name):
        """
        Return the DO definition from the resolved LNodeType,
        including inherited DOs.
        """
        return self.type_data_objects.get(name)

    def has_data_object(self, name):
        """
        True if the DO is instantiated as a DOI.
        """
        return self.get_data_object(name) is not None

    def has_defined_data_object(self, name):
        """
        True if the DO exists in the resolved LNodeType.
        """
        return self.get_defined_data_object(name) is not None

    def get_data_object_names(self):
        """
        Return names of instantiated DOIs.
        """
        return [
            data_object.name
            for data_object in self.data_objects
            if data_object.name
        ]

    def get_defined_data_object_names(self):
        """
        Return names of all DOs defined by the resolved LNodeType.
        """
        return list(self.type_data_objects.keys())


class DataObject:

    def __init__(
        self,
        element,
        logical_node,
        inherited=False
    ):

        self.element = element
        self.logical_node = logical_node

        self.name = element.get("name")
        self.type = element.get("type")
        self.desc = element.get("desc")

        self.inherited = inherited

        self.data_attributes = []
        self.sub_data_objects = []

        self._parse_children()

    def _parse_children(self):
        """
        Parse direct DAI and SDI children.

        SDIs are represented as nested DataObject objects so that
        paths such as:

            WMaxSptPct.mxVal.f

        can be resolved.
        """
        for child in children(self.element, "DAI"):
            self.data_attributes.append(
                DataAttribute(
                    child,
                    self
                )
            )

        for child in children(self.element, "SDI"):
            self.sub_data_objects.append(
                DataObject(
                    child,
                    self.logical_node,
                    inherited=self.inherited
                )
            )

    def get_data_attribute(self, name):
        """
        Return a direct DAI with the specified name.
        """
        for data_attribute in self.data_attributes:
            if data_attribute.name == name:
                return data_attribute

        return None

    def get_sub_data_object(self, name):
        """
        Return a direct SDI with the specified name.
        """
        for sub_data_object in self.sub_data_objects:
            if sub_data_object.name == name:
                return sub_data_object

        return None

    def get_path(self):
        """
        Return the hierarchical DOI/SDI name path.
        """
        parts = [self.name]

        current = self

        while isinstance(current, DataObject):
            parent = current.element

            # Find the owning DOI/SDI by walking through the XML model.
            found_parent = None

            for data_object in self.logical_node.data_objects:
                if data_object is current:
                    found_parent = None
                    break

            # The simple public path is reconstructed below.
            break

        return ".".join(
            part for part in parts
            if part
        )

    def find_path(self, path):
        """
        Resolve a path relative to this DataObject.

        Examples:

            WMaxSptPct.mxVal
            mxVal
        """
        if not path:
            return self

        parts = path.split(".")

        current = self

        if parts and parts[0] == self.name:
            parts = parts[1:]

        for part in parts:
            current = current.get_sub_data_object(part)

            if current is None:
                return None

        return current


class DataAttribute:

    def __init__(
        self,
        element,
        data_object
    ):

        self.element = element
        self.data_object = data_object

        self.name = element.get("name")
        self.b_type = element.get("bType")
        self.type = element.get("type")
        self.fc = element.get("fc")
        self.val_kind = element.get("valKind")

        self.values = []

        for val in children(
            element,
            "Val"
        ):
            self.values.append(
                val.text if val.text is not None else ""
            )

    @property
    def value(self):
        """
        Return the first Val value, or None.
        """
        if not self.values:
            return None

        return self.values[0]

    def get_values(self):
        return list(self.values)