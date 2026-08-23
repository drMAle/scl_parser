from model.scl_model import SCLModel

def build_model(filename):
    return SCLModel(filename).load()
