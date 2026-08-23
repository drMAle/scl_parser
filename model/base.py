"""Common base class for IEC 61850 configuration/observation models."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path

class Model(ABC):
    """Common interface consumed by validators and comparison code.

    Concrete models differ only in how the model is built from the source:
    SCLModel reads XML; PcapModel reconstructs information from MMS discovery.
    """
    source_type = "unknown"
    def __init__(self, filename):
        self.filename = Path(filename)
        self.loaded = False
        self.ieds = []
        self.tree = None
        self.root = None
    @abstractmethod
    def load(self):
        raise NotImplementedError
    @property
    def source_name(self):
        return self.filename.name
