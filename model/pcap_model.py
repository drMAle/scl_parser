"""PCAP/MMS observation model implementing the common Model interface."""
from __future__ import annotations
import re, struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from .base import Model

@dataclass
class PcapPacket:
    number: int; timestamp: float; src: str; dst: str; protocol: str
    src_port: int|None=None; dst_port: int|None=None; payload: bytes=b""; tcp_seq: int|None=None
@dataclass
class RuntimeDataAttribute:
    name: str; path: str; type: str; tag: int|None=None; constructed: bool=False
@dataclass
class RuntimeDataObject:
    object_name: str; data_objects: list[str]=field(default_factory=list)
    data_attributes: list[RuntimeDataAttribute]=field(default_factory=list); mms_deletable: bool|None=None
@dataclass
class GetVariableAccessAttributesTransaction:
    request_direction: str; response_direction: str; invoke_id: int|None; object_name: str|None
    attributes: dict=field(default_factory=dict); data_object: RuntimeDataObject|None=None
@dataclass
class GetNameListTransaction:
    request_direction: str; response_direction: str; invoke_id: int|None; object_class: int|None
    object_scope: str|None; domain_name: str|None; continue_after: str|None
    identifiers: list[str]=field(default_factory=list); more_follows: bool|None=None

class PcapModel(Model):
    source_type='pcap'
    def __init__(self, filename):
        super().__init__(filename)
        self.packets=[]; self.mms_packets=[]; self.discovery_packets=[]
        self.printable_tokens=set(); self.parse_warnings=[]; self.mms_messages=[]; self.mms_warnings=[]
        self.get_name_list=[]; self.get_variable_access_attributes=[]; self.runtime_data_objects={}
        self.named_variable_list_attributes=[]
        self.observed_identifiers=set(); self.observation={}
        self.discovery_evidence = {}
        self.required_discovery_stages = [
            'getNameList',
            'getVariableAccessAttributes',
            # These are required to claim a complete IEC 61850 discovery, but
            # are intentionally not marked as observed until their ASN.1
            # decoding is implemented.
            'getServerDirectory',
            'getLogicalDeviceDirectory',
            'getLogicalNodeDirectory',
            'getDataDirectory',
            'getDataSetDirectory',
        ]

    def load(self):
        self.packets=[]; self.mms_packets=[]; self.discovery_packets=[]; self.printable_tokens=set()
        self.parse_warnings=[]; self.mms_messages=[]; self.mms_warnings=[]; self.get_name_list=[]
        self.get_variable_access_attributes=[]; self.runtime_data_objects={}; self.named_variable_list_attributes=[]
        self.observed_identifiers=set(); self.observation={}; self.ieds=[]; self.tree=None; self.root=None
        self.discovery_evidence = {}
        data=self.filename.read_bytes()
        if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'): self._parse_pcap(data)
        elif data[:4]==b'\x0a\x0d\x0d\x0a': self._parse_pcapng(data)
        else: raise ValueError('Unsupported capture format: expected PCAP or PCAPNG')
        self.mms_packets=[p for p in self.packets if p.protocol=='TCP' and (p.src_port==102 or p.dst_port==102)]
        self.discovery_packets=[p for p in self.mms_packets if _looks_like_mms_discovery(p.payload)]
        for packet in self.mms_packets:
            self.printable_tokens.update(_extract_tokens(packet.payload))
        self._decode_mms_streams(); self._build_discovery_evidence(); self._build_observation_model(); self._build_observation_metadata(); self.loaded=True; return self

    @property
    def packet_count(self): return len(self.packets)
    @property
    def mms_count(self): return len(self.mms_packets)
    @property
    def discovery_count(self): return len(self.discovery_packets)

    def _decode_mms_streams(self):
        from mms_decoder import decode_stream
        flows={}
        for p in self.mms_packets:
            if p.src_port is None or p.dst_port is None or p.tcp_seq is None: continue
            key=(p.src,p.src_port,p.dst,p.dst_port); flows.setdefault(key,[]).append(p)
        for key, packets in flows.items():
            packets.sort(key=lambda p:(p.tcp_seq if p.tcp_seq is not None else 0,p.number))
            direction=f'{key[0]}:{key[1]} -> {key[2]}:{key[3]}'
            result=decode_stream(b''.join(p.payload for p in packets), direction)
            self.mms_messages.extend(result.messages); self.mms_warnings.extend(result.warnings)
        self._correlate_get_name_list(); self._correlate_get_variable_access_attributes(); self._correlate_named_variable_list_attributes()

    def _correlate_get_name_list(self):
        self.get_name_list=[]
        requests=[m for m in self.mms_messages if m.service=='getNameList' and m.direction.split(' -> ')[0].rsplit(':',1)[-1] != '102']
        responses=[m for m in self.mms_messages if m.service=='getNameList' and m.direction.split(' -> ')[0].rsplit(':',1)[-1] == '102']
        used=set()
        for req in requests:
            for idx,resp in enumerate(responses):
                if idx in used or req.invoke_id != resp.invoke_id: continue
                a,b=req.direction.split(' -> '); c,d=resp.direction.split(' -> ')
                if a==d and b==c:
                    self.get_name_list.append(GetNameListTransaction(req.direction,resp.direction,req.invoke_id,req.object_class,req.object_scope,req.domain_name,req.continue_after,resp.identifiers,resp.more_follows)); used.add(idx); break

    def _correlate_get_variable_access_attributes(self):
        self.get_variable_access_attributes=[]
        requests=[m for m in self.mms_messages if m.service=='getVariableAccessAttributes' and m.object_name]
        responses=[m for m in self.mms_messages if m.service=='getVariableAccessAttributes' and m.variable_attributes is not None]
        used=set()
        for req in requests:
            for idx,resp in enumerate(responses):
                if idx in used or req.invoke_id != resp.invoke_id: continue
                a,b=req.direction.split(' -> '); c,d=resp.direction.split(' -> ')
                if a!=d or b!=c: continue
                attrs=resp.variable_attributes or {}; comps=attrs.get('components',[])
                runtime=RuntimeDataObject(req.object_name or '', data_attributes=[RuntimeDataAttribute(item.get('name',''),item.get('path',''),item.get('type','unknown'),item.get('tag'),item.get('constructed',False)) for item in comps if item.get('name')], mms_deletable=attrs.get('mmsDeletable'))
                self.runtime_data_objects[runtime.object_name]=runtime
                self.get_variable_access_attributes.append(GetVariableAccessAttributesTransaction(req.direction,resp.direction,req.invoke_id,req.object_name,attrs,runtime)); used.add(idx); break

    def _correlate_named_variable_list_attributes(self):
        self.named_variable_list_attributes = []
        requests = [m for m in self.mms_messages
                    if m.service == 'getNamedVariableListAttributes' and m.object_name]
        responses = [m for m in self.mms_messages
                     if m.service == 'getNamedVariableListAttributes' and m.named_variable_list_attributes is not None]
        used = set()
        for req in requests:
            for idx, resp in enumerate(responses):
                if idx in used or req.invoke_id != resp.invoke_id:
                    continue
                a, b = req.direction.split(' -> '); c, d = resp.direction.split(' -> ')
                if a != d or b != c:
                    continue
                attrs = resp.named_variable_list_attributes or {}
                self.named_variable_list_attributes.append({
                    'request_direction': req.direction,
                    'response_direction': resp.direction,
                    'invoke_id': req.invoke_id,
                    'object_name': req.object_name,
                    **attrs,
                })
                used.add(idx)
                break

    def _build_discovery_evidence(self):
        """Record only discovery stages directly supported by decoded MMS evidence."""
        stages = {}
        for tx in self.get_name_list:
            if tx.object_class == 9 and tx.object_scope == 'vmdSpecific':
                stages['getServerDirectory'] = True
            if tx.object_class == 0 and tx.object_scope == 'domainSpecific':
                # A response with plain LN identifiers proves LN directory
                # enumeration; identifiers containing '$' prove lower-level
                # named-variable enumeration.
                if any('$' not in x for x in tx.identifiers):
                    stages['getLogicalNodeDirectory'] = True
                if any('$' in x for x in tx.identifiers):
                    stages['getDataDirectory'] = True
            if tx.object_class == 2 and tx.object_scope == 'domainSpecific':
                stages['getDataSetDirectory'] = True
        if self.get_variable_access_attributes:
            stages['getDataDefinition'] = True
        if self.named_variable_list_attributes:
            stages['getDataSetDirectory'] = True
        self.discovery_evidence = stages

    def _build_observation_model(self):
        """Build an XML-shaped observation tree exclusively from decoded facts.

        The tree is deliberately sparse: no node is created unless a packet
        supplied enough evidence for that node.  The common SCL object classes
        are reused so the validators can consume both model types.
        """
        root = ET.Element('SCL', {'version': 'observed'})
        ied_el = ET.SubElement(root, 'IED', {'name': self._observed_ied_name()})
        ap_el = ET.SubElement(ied_el, 'AccessPoint')
        server_el = ET.SubElement(ap_el, 'Server')
        ld_map = {}

        def ensure_ld(name):
            name = name or '<unknown-LD>'
            if name not in ld_map:
                ld_map[name] = ET.SubElement(server_el, 'LDevice', {'inst': name})
            return ld_map[name]

        def split_ln(identifier):
            identifier = identifier or ''
            if identifier == 'LLN0':
                return ('', 'LLN0', '0', True)
            m = re.search(r'^(.*?)([A-Z][A-Z0-9]{3})(\d+)$', identifier)
            if m:
                return m.group(1), m.group(2), m.group(3), False
            return '', identifier, '', False

        ln_map = {}
        do_map = {}

        def ensure_ln(ld_el, ld_name, ln_name):
            key = (ld_name, ln_name)
            if key in ln_map:
                return ln_map[key]
            prefix, ln_class, inst, is_ln0 = split_ln(ln_name)
            attrs = {'lnClass': ln_class}
            if not is_ln0 and inst:
                attrs['inst'] = inst
            if prefix:
                attrs['prefix'] = prefix
            tag = 'LN0' if is_ln0 else 'LN'
            ln_el = ET.SubElement(ld_el, tag, attrs)
            ln_map[key] = ln_el
            return ln_el

        def ensure_path(ld_name, path):
            parts = [x for x in re.split(r'[.$]', path) if x]
            if not parts:
                return
            ln_name = parts[0]
            ld_el = ensure_ld(ld_name)
            ln_el = ensure_ln(ld_el, ld_name, ln_name)
            parts = parts[1:]
            # Functional constraint is an MMS naming component, not an IEC DO.
            if parts and len(parts[0]) <= 3 and parts[0].upper() == parts[0] and parts[0] not in ('DO', 'DA'):
                parts = parts[1:]
            if not parts:
                return
            do_name = parts[0]
            key = (ld_name, ln_name, do_name)
            do_el = do_map.get(key)
            if do_el is None:
                do_el = ET.SubElement(ln_el, 'DOI', {'name': do_name})
                do_map[key] = do_el
            parent = do_el
            for part in parts[1:]:
                # Last component is a DAI; intermediate components are SDI.
                existing = next((x for x in list(parent) if x.get('name') == part and x.tag in ('SDI','DAI')), None)
                if existing is not None:
                    parent = existing
                    continue
                if part == parts[-1]:
                    parent = ET.SubElement(parent, 'DAI', {'name': part})
                else:
                    parent = ET.SubElement(parent, 'SDI', {'name': part})

        # Server directory gives logical-device names.
        for tx in self.get_name_list:
            if tx.object_class == 9 and tx.object_scope == 'vmdSpecific':
                for ld_name in tx.identifiers:
                    ensure_ld(ld_name)

        # LN/data-directory responses are domain-scoped.
        for tx in self.get_name_list:
            if tx.object_class == 0 and tx.object_scope == 'domainSpecific':
                domain = tx.domain_name or '<unknown-LD>'
                ld_el = ensure_ld(domain)
                for identifier in tx.identifiers:
                    if '$' not in identifier:
                        ensure_ln(ld_el, domain, identifier)
                    else:
                        ensure_path(domain, identifier)

        # VariableAccessAttributes names provide exact DO/DA type evidence.
        for tx in self.get_variable_access_attributes:
            if not tx.object_name:
                continue
            domain, sep, item = tx.object_name.partition('/')
            if sep:
                ensure_path(domain, item)
            attrs = tx.attributes.get('components', []) if tx.attributes else []
            # Components are relative to the requested named variable.
            for component in attrs:
                rel = component.get('path') or component.get('name')
                if rel:
                    ensure_path(domain, f'{item}.{rel}')

        # Dataset directory evidence is represented as DataSet/FCDA, with no
        # invented control-block definitions.
        for ds in self.named_variable_list_attributes:
            obj = ds.get('object_name') or ''
            domain, sep, item = obj.partition('/')
            if not sep:
                continue
            ln_name, _, ds_name = item.partition('$')
            if not ds_name:
                ds_name = item
            ld_el = ensure_ld(domain)
            ln_el = ensure_ln(ld_el, domain, ln_name or 'LLN0')
            ds_el = next((x for x in list(ln_el) if x.tag == 'DataSet' and x.get('name') == ds_name), None)
            if ds_el is None:
                ds_el = ET.SubElement(ln_el, 'DataSet', {'name': ds_name})
            for member in ds.get('variables', []):
                m_domain, m_sep, m_item = member.partition('/')
                ref = m_item if m_sep else member
                ln_ref, _, do_ref = ref.partition('$')
                if not do_ref:
                    do_ref = ref
                prefix, ln_class, ln_inst, _ = split_ln(ln_ref)
                fcda_attrs = {'ldInst': m_domain or domain, 'lnClass': ln_class, 'lnInst': ln_inst, 'doName': do_ref}
                ET.SubElement(ds_el, 'FCDA', fcda_attrs)

        self.root = root
        self.tree = ET.ElementTree(root)
        # Reuse the exact SCL object wrappers.  No SCL data is imported.
        from model.scl_model import SCLModel
        self.lnode_types = {}; self.do_types = {}; self.da_types = {}; self.enum_types = {}
        SCLModel._parse_ieds(self)

    def _observed_ied_name(self):
        identities = [m.server_identity for m in self.mms_messages if m.server_identity]
        # Identify does not define an IEC 61850 IED name. It is therefore kept
        # as metadata, never substituted into the IED name.
        return ''

    def _build_observation_metadata(self):
        self.observed_identifiers = set()
        for tx in self.get_name_list:
            self.observed_identifiers.update(tx.identifiers)
            if tx.domain_name:
                self.observed_identifiers.add(f'LD:{tx.domain_name}')
        for tx in self.get_variable_access_attributes:
            if tx.object_name:
                self.observed_identifiers.add(tx.object_name)
        for tx in self.named_variable_list_attributes:
            if tx.get('object_name'):
                self.observed_identifiers.add(tx['object_name'])
        self.observation = {
            'services': sorted({m.service for m in self.mms_messages}),
            'name_lists': self.get_name_list,
            'variable_access_attributes': self.get_variable_access_attributes,
            'named_variable_list_attributes': self.named_variable_list_attributes,
            'runtime_data_objects': self.runtime_data_objects,
            'observed_identifiers': sorted(self.observed_identifiers),
            'discovery_evidence': dict(self.discovery_evidence),
        }

    # packet parsing retained from previous implementation
    def _parse_pcap(self,data):
        magic=data[:4]; endian='<' if magic==b'\xd4\xc3\xb2\xa1' else '>'
        if len(data)<24: raise ValueError('PCAP header is truncated')
        _,_,_,_,_,_,network=struct.unpack(endian+'IHHIIII',data[:24]); offset=24; number=0
        while offset+16<=len(data):
            ts_sec,ts_frac,incl_len,_=struct.unpack(endian+'IIII',data[offset:offset+16]); offset+=16
            payload=data[offset:offset+incl_len]; offset+=incl_len
            if len(payload)!=incl_len: self.parse_warnings.append('Truncated packet at end of PCAP'); break
            number+=1; p=_decode_link_packet(number,ts_sec+ts_frac/1_000_000.0,payload,network)
            if p: self.packets.append(p)

    def _parse_pcapng(self,data):
        offset=0; interfaces={}; number=0
        while offset+12<=len(data):
            block_type,block_len=struct.unpack('<II',data[offset:offset+8])
            if block_len<12 or offset+block_len>len(data): self.parse_warnings.append('Invalid/truncated PCAPNG block'); break
            block=data[offset:offset+block_len]
            if block_type==1 and len(block)>=20: interfaces[len(interfaces)]=struct.unpack('<H',block[8:10])[0]
            elif block_type==6 and len(block)>=32:
                interface_id,ts_hi,ts_lo,cap_len=struct.unpack('<IIII',block[8:24]); raw=block[28:28+cap_len]
                number+=1; p=_decode_link_packet(number,((ts_hi<<32)|ts_lo)/1_000_000.0,raw,interfaces.get(interface_id,1))
                if p:self.packets.append(p)
            offset+=block_len

def _decode_link_packet(number,timestamp,raw,network):
    if network==1:
        if len(raw)<14:return None
        ethertype=struct.unpack('!H',raw[12:14])[0]
        if ethertype==0x0800:return _decode_ipv4(number,timestamp,raw[14:])
        return PcapPacket(number,timestamp,'','',f'ETHERTYPE 0x{ethertype:04x}',payload=raw[14:])
    if network==101:return _decode_ipv4(number,timestamp,raw)
    if network==113 and len(raw)>=16 and struct.unpack('!H',raw[14:16])[0]==0x0800:return _decode_ipv4(number,timestamp,raw[16:])
    return PcapPacket(number,timestamp,'','', 'LINK',payload=raw)

def _decode_ipv4(number,timestamp,raw):
    if len(raw)<20:return None
    if raw[0]>>4!=4:return None
    ihl=(raw[0]&15)*4
    if len(raw)<ihl:return None
    proto=raw[9]; src='.'.join(map(str,raw[12:16])); dst='.'.join(map(str,raw[16:20])); transport=raw[ihl:]
    if proto==6 and len(transport)>=20:
        sp,dp=struct.unpack('!HH',transport[:4]); off=((transport[12]>>4)&15)*4; payload=transport[off:] if len(transport)>=off else b''; seq=struct.unpack('!I',transport[4:8])[0]
        return PcapPacket(number,timestamp,src,dst,'TCP',sp,dp,payload,seq)
    if proto==17 and len(transport)>=8:
        sp,dp=struct.unpack('!HH',transport[:4]); return PcapPacket(number,timestamp,src,dst,'UDP',sp,dp,transport[8:])
    return PcapPacket(number,timestamp,src,dst,str(proto),payload=transport)

def _extract_tokens(payload):
    text=payload.decode('utf-8',errors='ignore')
    for m in re.finditer(r'[A-Za-z_][A-Za-z0-9_.:/-]{2,127}',text): yield m.group(0)
def _looks_like_mms_discovery(payload):
    text=payload.decode('utf-8',errors='ignore').lower()
    return any(x in text for x in ('getserverdirectory','getlogicaldevicedirectory','getlogicalnodedirectory','getdatadirectory','getdatasetdirectory','getnamedvariablelistattributes','read'))
