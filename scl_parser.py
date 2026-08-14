"""Backward-compatible import layer.

The effective IEC 61850 model now lives in model.py. Existing code that imports
SCLModel or XML helpers from scl_parser continues to work.
"""
from model import *
