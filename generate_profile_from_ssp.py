#!/usr/bin/env python3
"""
Generate an OSCAL Profile from a System Security Plan (SSP)

This script takes an OSCAL SSP YAML file as input and generates a corresponding
OSCAL profile YAML file containing the controls implemented in the SSP.
"""

import argparse
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Union
from uuid import uuid4

import yaml

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_yaml(file_path: Union[str, Path]) -> Dict:
    """
    Load a YAML file and return its contents as a dictionary.

    Args:
        file_path: Path to the YAML file

    Returns:
        Dictionary containing the YAML file contents

    Raises:
        Exception: If the file cannot be loaded or parsed
    """
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Error loading YAML file {file_path}: {e}")
        raise

def extract_controls_from_ssp(ssp_data: Dict) -> List[str]:
    """
    Extract control IDs from the SSP's implemented requirements.

    Args:
        ssp_data: Dictionary containing the SSP data

    Returns:
        List of control IDs
    """
    try:
        control_ids = []
        implemented_requirements = ssp_data.get('system-security-plan', {}).get(
            'control-implementation', {}).get('implemented-requirements', [])

        for requirement in implemented_requirements:
            control_id = requirement.get('control-id')
            if control_id:
                control_ids.append(control_id)

        return sorted(control_ids)
    except Exception as e:
        logger.error(f"Error extracting controls from SSP: {e}")
        raise

def create_profile(control_ids: List[str], ssp_data: Dict) -> Dict:
    """
    Create an OSCAL profile structure with the extracted controls.

    Args:
        control_ids: List of control IDs to include in the profile
        ssp_data: Dictionary containing the SSP data (for metadata reference)

    Returns:
        Dictionary containing the profile data
    """
    # Get SSP metadata for reference
    ssp_metadata = ssp_data.get('system-security-plan', {}).get('metadata', {})
    ssp_title = ssp_metadata.get('title', 'Unknown System')

    # Create profile structure
    current_timestamp = datetime.now(timezone.utc).isoformat()
    party_uuid = str(uuid4())

    profile = {
        'profile': {
            'uuid': str(uuid4()),
            'metadata': {
                'title': f"Profile for {ssp_title}",
                'last-modified': current_timestamp,
                'version': '1.0.0',
                'oscal-version': ssp_metadata.get('oscal-version', '1.0.4'),
                'roles': [
                    {
                        'id': 'creator',
                        'title': 'Document Creator'
                    },
                    {
                        'id': 'contact',
                        'title': 'Contact'
                    }
                ],
                'parties': [
                    {
                        'uuid': party_uuid,
                        'type': 'organization',
                        'name': 'Generated Profile',
                        'email-addresses': [
                            'example@example.com'
                        ]
                    }
                ],
                'responsible-parties': [
                    {
                        'role-id': 'creator',
                        'party-uuids': [
                            party_uuid
                        ]
                    }
                ]
            },
            'imports': [
                {
                    'href': 'https://raw.githubusercontent.com/usnistgov/oscal-content/ba2efa4c90155650b0fd536f3bffd13042ac6dc7/nist.gov/SP800-53/rev5/yaml/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.yaml',
                    'include-controls': [
                        {
                            'with-ids': control_ids
                        }
                    ]
                }
            ],
            'merge': {
                'as-is': True
            }
        }
    }

    return profile

def save_yaml(data: Dict, file_path: Union[str, Path]) -> None:
    """
    Save a dictionary as a YAML file.

    Args:
        data: Dictionary to save
        file_path: Path where the YAML file will be saved

    Raises:
        Exception: If the file cannot be saved
    """
    try:
        with open(file_path, 'w') as file:
            yaml.dump(data, file, default_flow_style=False, sort_keys=False)
        logger.info(f"Profile saved to {file_path}")
    except Exception as e:
        logger.error(f"Error saving YAML file {file_path}: {e}")
        raise

def validate_profile(profile_data: Dict) -> bool:
    """
    Perform basic validation on the generated profile.

    Args:
        profile_data: Dictionary containing the profile data

    Returns:
        True if the profile is valid, False otherwise
    """
    try:
        # Check for required fields
        if not profile_data.get('profile', {}).get('uuid'):
            logger.error("Profile is missing a UUID")
            return False

        if not profile_data.get('profile', {}).get('metadata', {}).get('title'):
            logger.error("Profile is missing a title")
            return False

        if not profile_data.get('profile', {}).get('imports'):
            logger.error("Profile is missing imports")
            return False

        # Check that there are controls
        controls = profile_data.get('profile', {}).get('imports', [{}])[0].get(
            'include-controls', [{}])[0].get('with-ids', [])

        if not controls:
            logger.error("Profile does not include any controls")
            return False

        return True
    except Exception as e:
        logger.error(f"Error validating profile: {e}")
        return False

def update_ssp_with_profile_reference(ssp_data: Dict, profile_path: str) -> Dict:
    """
    Update the SSP to reference the newly created profile.

    Args:
        ssp_data: Dictionary containing the SSP data
        profile_path: Path to the profile file

    Returns:
        Updated SSP data
    """
    try:
        # Make a deep copy to avoid modifying the original
        updated_ssp = dict(ssp_data)

        # Update the import-profile section
        if 'system-security-plan' in updated_ssp:
            updated_ssp['system-security-plan']['import-profile'] = {
                'href': profile_path
            }

        return updated_ssp
    except Exception as e:
        logger.error(f"Error updating SSP: {e}")
        raise

def main():
    """Main function to parse arguments and generate the profile."""
    parser = argparse.ArgumentParser(
        description='Generate an OSCAL Profile from a System Security Plan (SSP)'
    )
    parser.add_argument(
        'ssp_file',
        help='Path to the input SSP YAML file'
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to the output profile YAML file (default: profile_from_ssp.yaml)',
        default='profile_from_ssp.yaml'
    )
    parser.add_argument(
        '--update-ssp',
        action='store_true',
        help='Update the SSP to reference the new profile'
    )
    parser.add_argument(
        '--updated-ssp-output',
        help='Path to save the updated SSP (default: updated_ssp.yaml)',
        default='updated_ssp.yaml'
    )

    args = parser.parse_args()

    try:
        # Load the SSP
        logger.info(f"Loading SSP from {args.ssp_file}")
        ssp_data = load_yaml(args.ssp_file)

        # Extract controls
        logger.info("Extracting controls from SSP")
        control_ids = extract_controls_from_ssp(ssp_data)
        logger.info(f"Found {len(control_ids)} controls: {', '.join(control_ids)}")

        # Create profile
        logger.info("Creating profile")
        profile_data = create_profile(control_ids, ssp_data)

        # Validate profile
        logger.info("Validating profile")
        if not validate_profile(profile_data):
            logger.error("Profile validation failed")
            return 1
        logger.info("Profile validation successful")

        # Save profile
        logger.info(f"Saving profile to {args.output}")
        save_yaml(profile_data, args.output)

        # Update SSP if requested
        if args.update_ssp:
            logger.info("Updating SSP to reference the new profile")
            updated_ssp = update_ssp_with_profile_reference(ssp_data, args.output)

            logger.info(f"Saving updated SSP to {args.updated_ssp_output}")
            save_yaml(updated_ssp, args.updated_ssp_output)
            logger.info("SSP update completed successfully")

        logger.info("Profile generation completed successfully")

    except Exception as e:
        logger.error(f"Error generating profile: {e}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())
