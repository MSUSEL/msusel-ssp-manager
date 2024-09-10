#!/usr/bin/env python3
from flask import Blueprint, request, jsonify, current_app as app
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader, select_autoescape
from os import path, PathLike, getcwd
from pathlib import Path
from typing import Union
from uuid import uuid4
from yaml import safe_dump, safe_load
import jmespath # A query language for json
import logging
import os


logging.basicConfig(level=logging.INFO)

generate_blueprint = Blueprint('generate', __name__)

profile_path="./oscal_schemas/profiles/profile.yaml"
ssp_path="./oscal_schemas/system-security-plans/generated_ssp.yaml"

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


def generateAP(oscal_doc):
    profile_dictionary = load_yaml(f"/shared/{oscal_doc.filename}") # Returns a dictionary from the yaml
    controls = extract_controls(profile_dictionary) 
    ap_renderer = Environment(loader=FileSystemLoader(templates_path))
    current_timestamp = datetime.now(timezone.utc).isoformat()

    with open("./generatedFiles/generated_ap.yaml", 'w') as fh:
        template = ap_renderer.get_template("ap.yaml.j2")
        ap = template.render({
            'ap_uuid': uuid4(),
            'ap_metadata_title': 'OSCAL Automated Assessment Plan Template',
            'ap_metadata_last_modified_timestamp': current_timestamp,
            'ssp_import_href': f"{ssp_path}",
            'controls': controls,})
        fh.write(ap)
        fh.close()

@generate_blueprint.route('/ssp', methods=['POST'])
def generate():
    if 'file' not in request.files:
        return 'No file part', 400
    oscal_doc = request.files['file']
    app.logger.info(f"Generate Route. Current working directory: {os.getcwd()}")
    app.logger.info(f"Saving {oscal_doc.filename} to: {app.config['UPLOAD_FOLDER']}")
    current_user = os.environ.get("USER", "appuser")  # Default to 'appuser' if USER env var is not set
    logging.info(f"Current User: {current_user}")
    logging.info(f"Current working directory: {os.getcwd()}")
    oscal_doc.save(os.path.join(app.config['UPLOAD_FOLDER'], oscal_doc.filename)) 
    if oscal_doc.filename == '':
        return 'No selected file', 400
    if oscal_doc:
        try:
            profile_dictionary = load_yaml(f"/shared/{oscal_doc.filename}") # Returns a dictionary from the yaml
            #logging.info(f"Profile dictionary: {profile_dictionary}")
            controls = extract_controls(profile_dictionary) 
            controls_uuids = [uuid4() for control in controls]
            ssp_renderer = Environment(loader=FileSystemLoader(templates_path))
            current_timestamp = datetime.now(timezone.utc).isoformat()

            # We are using Jinja2 to render the SSP template
            with open(f"{app.config['GENERATION_FOLDER']}/generated_ssp.yaml", 'w') as fh:
                app.logger.info(f"file path: {fh.name}")
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
                app.logger.info(f"SSP template written to: {fh.name}")
                fh.close() 
                app.logger.info(f"SSP template generated.")   
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
        generateAP(oscal_doc) 
        return jsonify(message="SSP template generated.", status=200), 200
