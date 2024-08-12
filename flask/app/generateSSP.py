#!/usr/bin/env python3
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader, select_autoescape
from os import path, PathLike
from pathlib import Path
from typing import Union
from uuid import uuid4
from yaml import safe_dump, safe_load
import jmespath # A query language for json


# TODO: Accept profile input in json format.

templates_path = './templates/'

# The path arg can be of type str, bytes, Path, Pathlike
def load_yaml(path: Union[str, bytes, Path, PathLike]):
    """Load an OSCAL Assessment Plan YAML file.
    """
    try:
        return safe_load(open(path, 'r')) # Returns a dictionary from the yaml file

    except Exception as err:
        raise err

def extract_controls(input_profile: dict) -> dict:
    return jmespath.search(f'"profile"."imports"[0]."include-controls"[0]."with-ids"', input_profile)


def generateAP(profile_path: str, ssp_path: str, ap_path: str):
    profile_dictionary = load_yaml(profile_path) # Returns a dictionary from the yaml
    controls = extract_controls(profile_dictionary) 
    ap_renderer = Environment(loader=FileSystemLoader(templates_path))
    current_timestamp = datetime.now(timezone.utc).isoformat()

    with open(ap_path, 'w') as fh:
        template = ap_renderer.get_template("ap.yaml.j2")
        ap = template.render({
            'ap_uuid': uuid4(),
            'ap_metadata_title': 'OSCAL Automated Assessment Plan Template',
            'ap_metadata_last_modified_timestamp': current_timestamp,
            'ssp_import_href': f"{ssp_path}",
            'controls': controls,})
        fh.write(ap)
        fh.close()


def generateSSP(profile_path: str, ssp_path: str):
    profile_dictionary = load_yaml(profile_path) # Returns a dictionary from the yaml
    controls = extract_controls(profile_dictionary) 
    controls_uuids = [uuid4() for control in controls]
    ssp_renderer = Environment(loader=FileSystemLoader(templates_path))
    current_timestamp = datetime.now(timezone.utc).isoformat()

    with open(ssp_path, 'w') as fh:
        template = ssp_renderer.get_template("ssp.yaml.j2")
        ssp = template.render({
            'ssp_uuid': uuid4(),
            'ssp_metadata_title': 'OSCAL_Automated_SSP_Template',
            'ssp_metadata_last_modified_timestamp': current_timestamp,
            'profile_import_href': f"{profile_path}",
            'information_type_uuid': uuid4(),
            'users_uuid': uuid4(),
            'components_uuid': uuid4(),
            'controls_uuids': controls_uuids,
            'controls': controls,})
        fh.write(ssp)
        fh.close()
        


def generateDocuments():
    generateSSP(profile_path="/shared/profile.yaml", ssp_path="/shared/ssp.yaml")
    #generateAP(profile_path="/shared/profile.yaml", ap_path="/shared/ap.yaml", ssp_path="/shared/ssp.yaml")
    
if __name__ == '__main__':
    generateDocuments()
