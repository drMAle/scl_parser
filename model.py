"""IEC 61850 SCL object model with effective type resolution.

The important distinction in this module is between the *instance* found in
LN/DOI/DAI elements and the *effective data model* obtained from LNodeType,
DOType and DAType definitions.  A DO/DA does not have to be repeated as a
DOI/DAI for the effective IEC 61850 model to contain it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple


def local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def children(element, name: str):
    return [c for c in list(element) if local_name(c.tag) == name]


def descendants(element, name: str):
    return [c for c in element.iter() if local_name(c.tag) == name]


def find_all(element, name: str):
    return descendants(element, name)


def find_direct(element, name: str):
    return children(element, name)


class SCLModel:
    def __init__(self, filename: str):
        self.filename = filename
        self.tree = None
        self.root = None
        self.ieds: List[IED] = []
        self.lnode_types: Dict[str, object] = {}
        self.do_types: Dict[str, object] = {}
        self.da_types: Dict[str, object] = {}
        self.enum_types: Dict[str, object] = {}

    def load(self):
        self.tree = ET.parse(self.filename)
        self.root = self.tree.getroot()
        self._parse_type_definitions()
        self._parse_ieds()
        return self

    def _parse_type_definitions(self):
        self.lnode_types.clear()
        self.do_types.clear()
        self.da_types.clear()
        self.enum_types.clear()
        for e in descendants(self.root, "LNodeType"):
            if e.get("id"):
                self.lnode_types[e.get("id")] = e
        for e in descendants(self.root, "DOType"):
            if e.get("id"):
                self.do_types[e.get("id")] = e
        for e in descendants(self.root, "DAType"):
            if e.get("id"):
                self.da_types[e.get("id")] = e
        for e in descendants(self.root, "EnumType"):
            if e.get("id"):
                self.enum_types[e.get("id")] = e

    def get_lnode_type(self, type_id):
        return self.lnode_types.get(type_id)

    def get_do_type(self, type_id):
        return self.do_types.get(type_id)

    def get_da_type(self, type_id):
        return self.da_types.get(type_id)

    def get_enum_type(self, type_id):
        return self.enum_types.get(type_id)

    @staticmethod
    def _base_ref(element):
        if element is None:
            return None
        return element.get("base") or element.get("baseType") or element.get("baseTypeId")

    def resolve_lnode_type(self, type_id: str, visited: Optional[Set[str]] = None):
        """Return effective DO definitions for an LNodeType, including inheritance."""
        visited = set() if visited is None else set(visited)
        if not type_id:
            return {}
        if type_id in visited:
            raise ValueError(f"Circular LNodeType inheritance detected: {type_id}")
        element = self.lnode_types.get(type_id)
        if element is None:
            return {}
        visited.add(type_id)
        result = {}
        base = self._base_ref(element)
        if base:
            result.update(self.resolve_lnode_type(base, visited))
        for do in children(element, "DO"):
            if do.get("name"):
                result[do.get("name")] = do
        return result

    def _parse_ieds(self):
        self.ieds = [IED(e, self) for e in descendants(self.root, "IED")]

    def get_ied(self, name):
        return next((i for i in self.ieds if i.name == name), None)


class IED:
    def __init__(self, element, model):
        self.element = element
        self.model = model
        self.name = element.get("name")
        self.ied_type = element.get("type")
        self.access_points = [AccessPoint(e, self) for e in children(element, "AccessPoint")]

    def get_access_point(self, name):
        return next((x for x in self.access_points if x.name == name), None)


class AccessPoint:
    def __init__(self, element, ied):
        self.element = element
        self.ied = ied
        self.name = element.get("name")
        self.servers = [Server(e, self) for e in children(element, "Server")]

    def get_server(self, name=None):
        if name is None:
            return self.servers[0] if self.servers else None
        return next((x for x in self.servers if x.name == name), None)


class Server:
    def __init__(self, element, access_point):
        self.element = element
        self.access_point = access_point
        self.name = element.get("name")
        self.l_devices = [LDevice(e, self) for e in children(element, "LDevice")]

    def get_l_device(self, inst=None, name=None):
        for ld in self.l_devices:
            if inst is not None and ld.inst == inst:
                return ld
            if name is not None and ld.name == name:
                return ld
        return None


class LDevice:
    def __init__(self, element, server):
        self.element = element
        self.server = server
        self.inst = element.get("inst")
        self.name = element.get("name")
        self.logical_nodes: List[LogicalNode] = []
        self.ln0 = None
        for e in children(element, "LN0"):
            if self.ln0 is None:
                self.ln0 = LogicalNode(e, self, True)
        for e in children(element, "LN"):
            self.logical_nodes.append(LogicalNode(e, self, False))

    @property
    def all_logical_nodes(self):
        return ([self.ln0] if self.ln0 is not None else []) + self.logical_nodes

    def find_logical_nodes(self, ln_class=None, prefix=None, inst=None):
        result = []
        for ln in self.all_logical_nodes:
            if ln_class is not None and ln.ln_class != ln_class:
                continue
            if prefix is not None and ln.prefix != prefix:
                continue
            if inst is not None and ln.inst != inst:
                continue
            result.append(ln)
        return result


class LogicalNode:
    def __init__(self, element, l_device, is_ln0=False):
        self.element = element
        self.l_device = l_device
        self.is_ln0 = is_ln0
        self.ln_class = element.get("lnClass")
        self.inst = element.get("inst")
        self.prefix = element.get("prefix", "")
        self.ln_type = element.get("lnType")
        self.data_objects = [DataObject(e, self, False) for e in children(element, "DOI")]
        self.type_data_objects = self.model.resolve_lnode_type(self.ln_type) if self.ln_type else {}

    @property
    def model(self):
        return self.l_device.server.access_point.ied.model

    @property
    def identifier(self):
        return f"{self.prefix}{self.ln_class or ''}{self.inst or ''}"

    def get_data_object(self, name):
        return next((d for d in self.data_objects if d.name == name), None)

    def get_defined_data_object(self, name):
        return self.type_data_objects.get(name)

    def has_data_object(self, name):
        """True when the DO is present in the effective LN model."""
        return self.get_data_object(name) is not None or self.get_defined_data_object(name) is not None

    def has_instantiated_data_object(self, name):
        return self.get_data_object(name) is not None

    def has_defined_data_object(self, name):
        return self.get_defined_data_object(name) is not None

    def get_data_object_names(self):
        return [d.name for d in self.data_objects if d.name]

    def get_defined_data_object_names(self):
        return list(self.type_data_objects.keys())

    def get_effective_data_object(self, name):
        """Return an EffectiveDataObject backed by the DOI if present, otherwise the LNodeType DO."""
        instance = self.get_data_object(name)
        definition = self.get_defined_data_object(name)
        if instance is None and definition is None:
            return None
        return EffectiveDataObject(self, name, instance, definition)

    def has_data_path(self, path: str) -> bool:
        return self.get_effective_path(path) is not None

    def get_effective_path(self, path: str):
        """Resolve a path against the effective IEC 61850 type model.

        Examples: Beh.stVal, WRtg.setMag, WMaxSptPct.mxVal.f.
        The returned object is an EffectivePath object, not necessarily a
        physical DAI in the LN instance.
        """
        parts = [p for p in path.split(".") if p]
        if not parts:
            return None
        do_name = parts.pop(0)
        effective_do = self.get_effective_data_object(do_name)
        if effective_do is None:
            return None
        return effective_do.resolve(parts)

    def has_instantiated_data_path(self, path: str) -> bool:
        """Check the actual DOI/SDI/DAI elements present in the LN instance."""
        parts = [p for p in path.split(".") if p]
        if not parts:
            return False
        current = self.get_data_object(parts.pop(0))
        if current is None:
            return False
        for index, part in enumerate(parts):
            if index == len(parts) - 1:
                return current.get_data_attribute(part) is not None
            current = current.get_sub_data_object(part)
            if current is None:
                return False
        return True


@dataclass
class EffectivePath:
    ln: LogicalNode
    path: str
    kind: str
    definition: object = None
    instance: object = None


class EffectiveDataObject:
    def __init__(self, ln, name, instance, definition):
        self.ln = ln
        self.name = name
        self.instance = instance
        self.definition = definition
        self.type_id = ((instance.type if instance is not None and instance.type else None) or (definition.get("type") if definition is not None else None))

    def resolve(self, parts: List[str]):
        if not parts:
            return EffectivePath(self.ln, self.name, "DO", self.definition, self.instance)

        current_type_id = self.type_id
        current_kind = "DOType"
        current_instance = self.instance
        path_parts = []

        for index, part in enumerate(parts):
            path_parts.append(part)
            last = index == len(parts) - 1

            if current_kind == "DOType":
                type_element = self.ln.model.get_do_type(current_type_id)
                if type_element is None:
                    return None
                child = next((x for x in list(type_element)
                              if local_name(x.tag) in ("DA", "SDO") and x.get("name") == part), None)
                if child is None:
                    return None
                child_kind = local_name(child.tag)
                if last:
                    inst_attr = current_instance.get_data_attribute(part) if current_instance and child_kind == "DA" else None
                    inst_sdo = current_instance.get_sub_data_object(part) if current_instance and child_kind == "SDO" else None
                    return EffectivePath(self.ln, f"{self.name}.{'.'.join(path_parts)}", child_kind, child, inst_attr or inst_sdo)
                if not child.get("type"):
                    return None
                current_type_id = child.get("type")
                current_kind = "DAType" if child_kind == "DA" and child.get("bType") == "Struct" else ("DOType" if child_kind == "SDO" else None)
                if current_kind is None:
                    return None
                if child_kind == "DA":
                    current_instance = current_instance.get_data_attribute(part) if current_instance else None
                else:
                    current_instance = current_instance.get_sub_data_object(part) if current_instance else None

            elif current_kind == "DAType":
                type_element = self.ln.model.get_da_type(current_type_id)
                if type_element is None:
                    return None
                child = next((x for x in list(type_element)
                              if local_name(x.tag) == "BDA" and x.get("name") == part), None)
                if child is None:
                    return None
                if last:
                    return EffectivePath(self.ln, f"{self.name}.{'.'.join(path_parts)}", "BDA", child, None)
                if child.get("bType") != "Struct" or not child.get("type"):
                    return None
                current_type_id = child.get("type")
                current_kind = "DAType"
                current_instance = None
            else:
                return None

        return None



class DataObject:
    def __init__(self, element, logical_node, inherited=False):
        self.element = element
        self.logical_node = logical_node
        self.name = element.get("name")
        self.type = element.get("type")
        self.desc = element.get("desc")
        self.inherited = inherited
        self.data_attributes = [DataAttribute(e, self) for e in children(element, "DAI")]
        self.sub_data_objects = [DataObject(e, logical_node, inherited) for e in children(element, "SDI")]

    def get_data_attribute(self, name):
        return next((x for x in self.data_attributes if x.name == name), None)

    def get_sub_data_object(self, name):
        return next((x for x in self.sub_data_objects if x.name == name), None)

    def find_path(self, path):
        parts = [p for p in path.split(".") if p]
        if parts and parts[0] == self.name:
            parts = parts[1:]
        current = self
        for part in parts:
            current = current.get_sub_data_object(part)
            if current is None:
                return None
        return current


class DataAttribute:
    def __init__(self, element, data_object):
        self.element = element
        self.data_object = data_object
        self.name = element.get("name")
        self.b_type = element.get("bType")
        self.type = element.get("type")
        self.fc = element.get("fc")
        self.val_kind = element.get("valKind")
        self.values = [v.text if v.text is not None else "" for v in children(element, "Val")]

    @property
    def value(self):
        return self.values[0] if self.values else None


__all__ = [
    "SCLModel", "IED", "AccessPoint", "Server", "LDevice", "LogicalNode",
    "DataObject", "DataAttribute", "EffectivePath", "EffectiveDataObject",
    "local_name", "children", "descendants", "find_all", "find_direct",
]
