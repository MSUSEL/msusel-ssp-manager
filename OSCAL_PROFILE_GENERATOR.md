# OSCAL Profile Generator

This tool generates an OSCAL profile from a System Security Plan (SSP). It extracts the control IDs from the SSP's implemented requirements and creates a valid OSCAL profile document.

## Overview

The Open Security Controls Assessment Language (OSCAL) is a series of formats developed by the National Institute of Standards and Technology (NIST) for the transmission of security control compliance information. This tool helps with the creation of OSCAL profiles based on existing SSPs.

## Features

- Extract control IDs from an SSP
- Generate a valid OSCAL profile in YAML format
- Validate the generated profile
- Optionally update the SSP to reference the new profile

## Requirements

- Python 3.6+
- PyYAML

## Installation

```bash
# Install required packages
pip install pyyaml
```

## Usage

```bash
# Basic usage
python3 generate_profile_from_ssp.py path/to/ssp.yaml -o output_profile.yaml

# Generate profile and update SSP to reference it
python3 generate_profile_from_ssp.py path/to/ssp.yaml -o output_profile.yaml --update-ssp --updated-ssp-output updated_ssp.yaml
```

### Command-line Arguments

- `ssp_file`: Path to the input SSP YAML file
- `-o, --output`: Path to the output profile YAML file (default: profile_from_ssp.yaml)
- `--update-ssp`: Update the SSP to reference the new profile
- `--updated-ssp-output`: Path to save the updated SSP (default: updated_ssp.yaml)

## Example

```bash
python3 generate_profile_from_ssp.py flask/oscal_schemas/system-security-plans/ssp.yaml -o generated_profile.yaml
```

This will:
1. Load the SSP from the specified path
2. Extract the control IDs from the SSP
3. Generate a profile with those controls
4. Save the profile to `generated_profile.yaml`

## OSCAL Document Structure

### Profile Structure

A generated profile will have the following structure:

```yaml
profile:
  uuid: [generated-uuid]
  metadata:
    title: Profile for [SSP Title]
    last-modified: [timestamp]
    version: 1.0.0
    oscal-version: [from SSP]
    roles:
      - id: creator
        title: Document Creator
      - id: contact
        title: Contact
    parties:
      - uuid: [generated-uuid]
        type: organization
        name: Generated Profile
        email-addresses:
          - example@example.com
    responsible-parties:
      - role-id: creator
        party-uuids:
          - [party-uuid]
  imports:
    - href: [NIST catalog URL]
      include-controls:
        - with-ids:
            - [control-id-1]
            - [control-id-2]
            # ...
  merge:
    as-is: true
```

## License

This project is open source and available under the [MIT License](LICENSE).
