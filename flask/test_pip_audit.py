#!/usr/bin/env python3
"""
Test script to run pip-audit on individually installed packages
and show the expected JSON output format.
"""

import subprocess
import json
import sys
import tempfile
import os
import logging

logging.basicConfig(level=logging.INFO)

def parseRequirements():
    """Parse requirements.txt into individual package specifications"""
    requirements_content = """requests
Flask==0.5
Babel==2.9.0
Django==3.1.13
urllib3==1.25.8
Jinja2==2.11.2
PyYAML==5.3.1
future==1.0.0
Pillow==9.0.0
lxml==4.6.2"""
    
    packages = []
    for line in requirements_content.strip().split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            packages.append(line)
    
    logging.info(f"Parsed {len(packages)} packages from requirements")
    return packages

def installRequirements(venv_path):
    """Install packages individually with error handling"""
    pip_path = f"{venv_path}/bin/pip"
    
    packages = parseRequirements()
    if not packages:
        logging.error("No packages to install")
        return []
    
    installation_results = []
    successful_packages = []
    failed_packages = []
    
    logging.info(f"Starting individual installation of {len(packages)} packages")
    
    for package in packages:
        package_result = {
            'package': package,
            'status': 'pending',
            'error_message': None
        }
        
        try:
            logging.info(f"Installing package: {package}")
            result = subprocess.run([pip_path, "install", package], 
                                  check=True, 
                                  capture_output=True, 
                                  text=True)
            
            package_result['status'] = 'success'
            successful_packages.append(package)
            logging.info(f"Successfully installed: {package}")
            
        except subprocess.CalledProcessError as e:
            package_result['status'] = 'failed'
            package_result['error_message'] = e.stderr.strip() if e.stderr else str(e)
            failed_packages.append(package)
            logging.warning(f"Failed to install {package}: {package_result['error_message']}")
        
        except Exception as e:
            package_result['status'] = 'failed'
            package_result['error_message'] = str(e)
            failed_packages.append(package)
            logging.warning(f"Unexpected error installing {package}: {str(e)}")
        
        installation_results.append(package_result)
    
    logging.info(f"Installation complete: {len(successful_packages)} successful, {len(failed_packages)} failed")
    logging.info(f"Successful packages: {successful_packages}")
    if failed_packages:
        logging.warning(f"Failed packages: {failed_packages}")
    
    return installation_results

def runPipAudit(venv_path):
    """Execute pip-audit on the virtual environment and return results"""
    pip_audit_path = f"{venv_path}/bin/pip-audit"
    
    try:
        logging.info("Running pip-audit on virtual environment")
        result = subprocess.run([pip_audit_path, "--format=json"], 
                              check=True, 
                              capture_output=True, 
                              text=True)
        
        logging.info("pip-audit completed successfully")
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        logging.warning(f"pip-audit failed: {e.stderr}")
        return None
    except FileNotFoundError:
        logging.error("pip-audit not found in virtual environment")
        return None
    except Exception as e:
        logging.warning(f"Unexpected error running pip-audit: {str(e)}")
        return None

def create_virtual_environment():
    """Create a virtual environment using the same Python version as production"""
    temp_dir = tempfile.mkdtemp()
    venv_path = os.path.join(temp_dir, "test_venv")
    
    try:
        logging.info(f"Creating virtual environment at {venv_path}")
        # Use the current Python (should be 3.10 to match Flask container)
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
        
        # Install pip-audit in the virtual environment (let it use whatever versions it wants)
        pip_path = f"{venv_path}/bin/pip"
        logging.info("Installing pip-audit in virtual environment")
        subprocess.run([pip_path, "install", "pip-audit"], check=True)
        
        return venv_path
    except Exception as e:
        logging.error(f"Failed to create virtual environment: {e}")
        return None

def parse_and_display_output(audit_output):
    """Parse and display the pip-audit JSON output"""
    if not audit_output:
        print("No audit output to parse")
        return
    
    try:
        audit_data = json.loads(audit_output)
        print(f"\n=== Parsed {len(audit_data)} packages ===")
        
        total_vulns = 0
        for package_data in audit_data:
            package_name = package_data.get('package', 'unknown')
            version = package_data.get('installed_version', 'unknown')
            vulns = package_data.get('vulnerabilities', [])
            
            print(f"\nPackage: {package_name} v{version}")
            print(f"Vulnerabilities: {len(vulns)}")
            
            for vuln in vulns:
                vuln_id = vuln.get('id', 'unknown')
                description = vuln.get('description', 'No description')[:100] + "..."
                fix_versions = vuln.get('fix_versions', [])
                
                print(f"  - {vuln_id}: {description}")
                print(f"    Fix versions: {fix_versions}")
                total_vulns += 1
        
        print(f"\n=== Summary ===")
        print(f"Total packages: {len(audit_data)}")
        print(f"Total vulnerabilities: {total_vulns}")
        
        # Show raw JSON structure for first package (if any)
        if audit_data:
            print(f"\n=== Sample JSON Structure ===")
            print(json.dumps(audit_data[0], indent=2))
            
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
        print("Raw output:")
        print(audit_output)

def main():
    print("Testing pip-audit with individual package installation...")
    
    # Create virtual environment
    venv_path = create_virtual_environment()
    if not venv_path:
        print("Failed to create virtual environment")
        return
    
    try:
        # Install packages individually
        installation_results = installRequirements(venv_path)
        
        # Show installation summary
        successful_count = sum(1 for r in installation_results if r['status'] == 'success')
        print(f"\nInstallation Summary: {successful_count}/{len(installation_results)} packages installed successfully")
        
        # Run pip-audit on successfully installed packages
        audit_output = runPipAudit(venv_path)
        
        if audit_output:
            print("\n=== Raw pip-audit output ===")
            print(audit_output[:500] + "..." if len(audit_output) > 500 else audit_output)
            
            # Parse and display
            parse_and_display_output(audit_output)
        else:
            print("Failed to get pip-audit output")
            
    finally:
        # Clean up virtual environment
        import shutil
        shutil.rmtree(os.path.dirname(venv_path))
        print(f"\nCleaned up virtual environment")

if __name__ == "__main__":
    main()
