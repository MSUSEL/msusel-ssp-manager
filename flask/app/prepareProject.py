# This program creates a virtual environment in the curtent directory.

import os
import sys
import subprocess
import platform
import importlib
import shutil
from downloadDependencies import download_Dependencies
from copySTDLIBfiles import copySTDLibFiles
from runBandit import runBandit
from parseBanditOutput import parseBandit
from getFunctionNames import getVulnerableFunctions
from parseProfile import getFilesAndFunctionNamesFromCallGraph
from matchVulnerabilitiesToCalls import matchVulnerableFunctionsToCalledFunctions
from prepareCWEList import prepareCWEList
import logging
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO)


# This function installs Python's venv module.
def installVenv():
    # Check if the venv module is installed
    try:
        importlib.import_module('venv')
        logging.info("The venv module is installed.")
    except ImportError:
        logging.info("The venv module is not installed. Will handle the installation.")
        # Handle: Install the venv module
        if platform.system() == "Windows":
            subprocess.run(["python", "-m", "pip", "install", "venv"])
        else:
            subprocess.run(["python3", "-m", "pip", "install", "venv"])
        # Check if the venv module was installed
        try:
            importlib.import_module('venv')
        except ImportError:
            logging.info("The venv module was not installed.")
            sys.exit()
        logging.info("The venv module was installed.")

def createVenv():
    # Get the current directory
    currentDir = os.getcwd()
    # Check if the current directory is a valid directory
    if not os.path.isdir(currentDir):
        logging.info("The current directory is not a valid directory.")
        sys.exit()
    # Create a venv virtual environment
    if platform.system() == "Windows":
        subprocess.run(["python", "-m", "venv", "venv"])
    else:
        subprocess.run(["python3", "-m", "venv", "venv"])
    # Check if the venv directory was created
    if not os.path.isdir("venv"):
        logging.info("The venv directory was not created.")
        sys.exit()
    # Print the message
    logging.info("The venv directory was created.")

# This function activates the virtual environment
def activateVenv():
    activate_command = "source venv/bin/activate"  # For Unix-based systems
    # activate_command = "my_venv\\Scripts\\activate"  # For Windows systems
    # call the shell explicitly
    subprocess.run(["/bin/bash", "-c", activate_command], check=True)
    logging.info("The virtual environment was activated.")

def parseRequirements():
    """Parse requirements.txt into individual package specifications"""
    currentDir = os.getcwd()
    requirements_path = f'{currentDir}/app/dependencies/requirements.txt'
    
    packages = []
    try:
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    packages.append(line)
        logging.info(f"Parsed {len(packages)} packages from requirements.txt")
        return packages
    except FileNotFoundError:
        logging.error(f"Requirements file not found: {requirements_path}")
        return []

def installRequirements():
    """Install packages individually with error handling"""
    currentDir = os.getcwd()
    pip_path = "venv/bin/pip"
    
    # Parse individual packages
    packages = parseRequirements()
    if not packages:
        logging.error("No packages to install")
        return []
    
    # Track installation results
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
    
    # Log summary
    logging.info(f"Installation complete: {len(successful_packages)} successful, {len(failed_packages)} failed")
    logging.info(f"Successful packages: {successful_packages}")
    if failed_packages:
        logging.warning(f"Failed packages: {failed_packages}")
    
    return installation_results

def listInstalledPackages():
    # List the installed packages in the virtual environment
    # Give the path to the pip executable
    pip_path = "venv/bin/pip"  # For Unix-based systems
    pip_list_output = subprocess.run([pip_path, "list"], check=True, text=True)
    logging.info("Packages installed in virtual environment:")
    print(pip_list_output.stdout)


def listAllDependencies():
    pip_path = "venv/bin/pip"  # For Unix-based systems. Give the path to the pip executable.
    with open('./app/artifacts/dependencies.txt', 'w') as f:
        subprocess.run([pip_path, 'freeze'], stdout=f)

def copyFile(filename):
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    originalPath = currentDir + "/app/" + filename
    logging.info(f"Original path: {originalPath}")
    newPath = currentDir + "/app/dependencies/" + filename
    logging.info(f"New path: {newPath}")
    shutil.copy(originalPath, newPath)
    return newPath

def removeFile(path):
    os.remove(path)

def profilerWrapper(module_name, function_name):
    newPath = copyFile('dynamicCallGraph.py')
    result = subprocess.run(["python3", "./app/dependencies/dynamicCallGraph.py", f'{module_name}', f'{function_name}'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logging.info(result.stdout.decode())
    logging.info(result.stderr.decode())
    removeFile(newPath)
    logging.info(f"Removed file: {newPath}")


def copyToSTDLib():
    # Define the source and destination file paths
    source_file = 'sqLib.py'
    destination_file = '/usr/local/lib/python3.10/sqLib.py'

    # Use subprocess.run to copy the file
    try:
        subprocess.run(['sudo', 'cp', source_file, destination_file], check=True)
        logging.info(f'Successfully copied {source_file} to {destination_file}')
    except subprocess.CalledProcessError as e:
        logging.info(f'Failed to copy file: {e}')

def runPipAudit():
    """Execute pip-audit on the virtual environment and return results"""
    pip_audit_path = "venv/bin/pip-audit"
    
    try:
        logging.info("Running pip-audit on virtual environment")
        result = subprocess.run([pip_audit_path, "--format=json"], 
                              capture_output=True, 
                              text=True)  # Removed check=True
        
        if result.returncode == 0:
            logging.info("pip-audit completed successfully - no vulnerabilities found")
        elif result.returncode == 1:
            logging.info("pip-audit completed successfully - vulnerabilities found")
        else:
            logging.warning(f"pip-audit returned unexpected code: {result.returncode}")
            
        return result.stdout
        
    except Exception as e:
        logging.warning(f"Unexpected error running pip-audit: {str(e)}")
        return None

def parsePipAuditOutput(audit_output):
    """Parse pip-audit JSON output and extract CVE information"""
    if not audit_output:
        logging.warning("No pip-audit output to parse")
        return []
    
    try:
        import json
        audit_data = json.loads(audit_output)
        
        # Handle new pip-audit format with "dependencies" wrapper
        if isinstance(audit_data, dict) and "dependencies" in audit_data:
            packages = audit_data["dependencies"]
        else:
            # Fallback for old format
            packages = audit_data
        
        vulnerabilities = []
        for package in packages:
            package_name = package.get('name') or package.get('package', 'unknown')
            package_version = package.get('version') or package.get('installed_version', 'unknown')
            vulns = package.get('vulns') or package.get('vulnerabilities', [])
            
            for vuln in vulns:
                # Extract actual CVE from aliases if available
                cve_id = vuln.get('id', '')
                aliases = vuln.get('aliases', [])
                
                # Look for CVE in aliases first
                actual_cve = None
                for alias in aliases:
                    if alias.startswith('CVE-'):
                        actual_cve = alias
                        break
                
                # Use actual CVE if found, otherwise use the ID
                final_cve = actual_cve or cve_id
                
                vuln_info = {
                    'package': package_name,
                    'version': package_version,
                    'cve': final_cve,
                    'original_id': cve_id,  # Keep original for reference
                    'fix_versions': vuln.get('fix_versions', []),
                    'description': vuln.get('description', '')
                }
                vulnerabilities.append(vuln_info)
        
        logging.info(f"Parsed {len(vulnerabilities)} vulnerabilities from pip-audit")
        return vulnerabilities
        
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse pip-audit JSON output: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error parsing pip-audit output: {str(e)}")
        return []

def matchAuditResultsToInstallation(installation_results, audit_vulnerabilities):
    """Correlate pip-audit findings with successfully installed packages"""
    # Create lookup for successful packages
    successful_packages = {result['package'].split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].split('!=')[0]: result 
                          for result in installation_results if result['status'] == 'success'}
    
    # Group vulnerabilities by package
    package_vulns = {}
    for vuln in audit_vulnerabilities:
        package_name = vuln['package']
        if package_name in successful_packages:
            if package_name not in package_vulns:
                package_vulns[package_name] = {
                    'package': package_name,
                    'version': vuln['version'],
                    'installation_status': 'success',
                    'vulns': []
                }
            
            # Add vulnerability to package's vuln list
            vuln_info = {
                'id': vuln['cve'],
                'description': vuln['description'],
                'fix_versions': vuln['fix_versions'],  # Now correctly mapped
                'severity': 'unknown'  # pip-audit doesn't provide severity directly
            }
            package_vulns[package_name]['vulns'].append(vuln_info)
    
    # Convert to list format
    matched_results = list(package_vulns.values())
    
    logging.info(f"Matched vulnerabilities for {len(matched_results)} packages")
    total_vulns = sum(len(pkg['vulns']) for pkg in matched_results)
    logging.info(f"Total vulnerabilities: {total_vulns}")
    
    return matched_results

def generateCVEList(matched_vulnerabilities):
    """Generate simple CVE list for backend processing"""
    cve_list = []
    seen_cves = set()  # Avoid duplicates
    
    for package_result in matched_vulnerabilities:
        vulns = package_result.get('vulns', [])
        for vuln in vulns:
            cve = vuln.get('id', '')  # Changed from 'cve' to 'id' to match structure
            if cve and cve not in seen_cves:
                cve_list.append({"cve": cve})
                seen_cves.add(cve)
    
    logging.info(f"Generated CVE list with {len(cve_list)} unique CVEs")
    return cve_list


# Not Called
def generateCVEListFromMatchedResults(matched_results):
    """
    Generate CVE list from matched audit results for backend processing
    
    Args:
        matched_results: List of dictionaries containing package audit results
        
    Returns:
        list: Simple list of CVE dictionaries in format [{"cve": "CVE-YYYY-NNNN"}, ...]
    """
    try:
        cve_list = []
        seen_cves = set()  # Avoid duplicates
        
        for package_result in matched_results:
            vulns = package_result.get('vulns', [])
            
            for vuln in vulns:
                cve_id = vuln.get('id', '')
                
                # Validate CVE format (CVE-YYYY-NNNN)
                if cve_id and cve_id.startswith('CVE-') and cve_id not in seen_cves:
                    cve_parts = cve_id.split('-')
                    if len(cve_parts) == 3 and cve_parts[1].isdigit() and cve_parts[2].isdigit():
                        cve_list.append({"cve": cve_id})
                        seen_cves.add(cve_id)
        
        # Sort CVE list for consistent output
        cve_list.sort(key=lambda x: x['cve'])
        
        logging.info(f"Generated CVE list with {len(cve_list)} unique CVEs")
        return cve_list
        
    except Exception as e:
        logging.error(f"Error generating CVE list: {e}")
        return []

def generatePackageReport(matched_results):
    """
    Generate detailed package audit report with installation status and vulnerabilities
    
    Args:
        matched_results: List of dictionaries containing package audit results
        
    Returns:
        dict: Comprehensive report with package details, vulnerabilities, and statistics
    """
    try:
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "package_vulnerability_audit",
                "total_packages": len(matched_results)
            },
            "summary": {
                "packages_with_vulnerabilities": 0,
                "total_vulnerabilities": 0,
                "packages_clean": 0,
                "packages_failed_audit": 0
            },
            "packages": []
        }
        
        for package_result in matched_results:
            package_name = package_result.get('package', 'unknown')
            installed_version = package_result.get('installed_version', 'unknown')
            vulns = package_result.get('vulns', [])
            audit_status = package_result.get('audit_status', 'success')
            
            package_info = {
                "name": package_name,
                "installed_version": installed_version,
                "requested_version": package_result.get('requested_version', installed_version),
                "installation_status": package_result.get('status', 'unknown'),
                "audit_status": audit_status,
                "vulnerability_count": len(vulns),
                "vulnerabilities": []
            }
            
            # Process vulnerabilities
            for vuln in vulns:
                vuln_info = {
                    "id": vuln.get('id', 'unknown'),
                    "description": vuln.get('description', 'No description available'),
                    "fix_versions": vuln.get('fix_versions', []),
                    "severity": vuln.get('severity', 'unknown')
                }
                package_info["vulnerabilities"].append(vuln_info)
            
            report["packages"].append(package_info)
            
            # Update summary statistics
            if len(vulns) > 0:
                report["summary"]["packages_with_vulnerabilities"] += 1
                report["summary"]["total_vulnerabilities"] += len(vulns)
            elif audit_status == 'no_audit_data':
                report["summary"]["packages_failed_audit"] += 1
            else:
                report["summary"]["packages_clean"] += 1
        
        return report
        
    except Exception as e:
        logging.error(f"Error generating package report: {e}")
        return {
            "error": "Failed to generate package report",
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "package_vulnerability_audit"
            }
        }

def writeOutputFiles(cve_list, package_report):
    """Write output files to shared directory"""
    import json
    import os
    
    try:
        # Ensure shared directory exists
        shared_dir = '/shared'
        os.makedirs(shared_dir, exist_ok=True)
        
        # Write CVE list
        cve_file_path = os.path.join(shared_dir, 'cve_list.json')
        with open(cve_file_path, 'w') as f:
            json.dump(cve_list, f, indent=2)
        logging.info(f"CVE list written to {cve_file_path}")
        
        # Write package audit report
        report_file_path = os.path.join(shared_dir, 'package_audit_report.json')
        with open(report_file_path, 'w') as f:
            json.dump(package_report, f, indent=2)
        logging.info(f"Package audit report written to {report_file_path}")
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to write output files: {str(e)}")
        return False

def mapCVEsToCWEs(cve_list):
    """
    Map CVEs from pip-audit to CWEs using BRON database
    """
    try:
        from db_queries import DatabaseConnection, DatabaseQueryService  # Remove the dot
        
        if not cve_list:
            logging.info("No CVEs to map, returning empty CWE list")
            return []
        
        # Extract CVE IDs from the list
        cve_ids = [item['cve'] for item in cve_list]
        logging.info(f"Mapping {len(cve_ids)} CVEs to CWEs: {cve_ids}")
        
        # Initialize database connection
        db_connection = DatabaseConnection()
        query_service = DatabaseQueryService(db_connection)
        
        # Use existing functionality to fetch attacks against CVEs
        cursor_attacks = query_service.fetch_attacks_against_cves(cve_ids)
        
        # Extract unique CWEs from the results
        cwe_set = set()
        for result in cursor_attacks:
            cves = result.get('cve', [])
            for cve_id in cves:
                # The BRON database links CVEs to CWEs through the attack mapping
                # We need to query for CWEs associated with these CVEs
                pass
        
        # Query CWEs directly associated with CVEs using full document IDs
        cwe_query = '''
            LET full_ids = (FOR cve_id IN @cve_list RETURN CONCAT("cve/", cve_id))
            FOR cve_id IN full_ids
                FOR edge IN CweCve
                    FILTER edge._to == cve_id
                    FOR cwe IN cwe
                        FILTER cwe._id == edge._from
                        RETURN DISTINCT cwe.original_id
        '''
        bind_vars = {'cve_list': cve_ids}
        cursor_cwes = db_connection.db.aql.execute(cwe_query, bind_vars=bind_vars)
        
        # Convert to the expected format
        cwe_list = []
        seen_cwes = set()
        
        for cwe_id in cursor_cwes:
            if cwe_id and cwe_id not in seen_cwes:
                cwe_list.append({"cwe": str(cwe_id)})
                seen_cwes.add(cwe_id)
        
        logging.info(f"Mapped CVEs to {len(cwe_list)} unique CWEs")
        return cwe_list
        
    except Exception as e:
        logging.error(f"Error mapping CVEs to CWEs: {e}")
        return []

def mergeCWEsFromPipAudit():
    """
    Merge CWEs mapped from pip-audit CVEs with existing CWEs in vulnerabilities.json
    """
    try:
        global pip_audit_mapped_cwes
        
        if not pip_audit_mapped_cwes:
            logging.info("No pip-audit CWEs to merge")
            return
        
        # Read existing CWEs from vulnerabilities.json
        vulnerabilities_path = '/shared/vulnerabilities.json'
        existing_cwes = []
        
        if os.path.exists(vulnerabilities_path):
            with open(vulnerabilities_path, 'r') as f:
                existing_cwes = json.load(f)
        
        # Merge and deduplicate
        seen_cwes = set()
        merged_cwes = []
        
        # Add existing CWEs
        for cwe_item in existing_cwes:
            cwe_id = cwe_item.get('cwe')
            if cwe_id and cwe_id not in seen_cwes:
                merged_cwes.append(cwe_item)
                seen_cwes.add(cwe_id)
        
        # Add pip-audit mapped CWEs
        for cwe_item in pip_audit_mapped_cwes:
            cwe_id = cwe_item.get('cwe')
            if cwe_id and cwe_id not in seen_cwes:
                merged_cwes.append(cwe_item)
                seen_cwes.add(cwe_id)
        
        # Write merged CWEs back to vulnerabilities.json
        with open(vulnerabilities_path, 'w') as f:
            json.dump(merged_cwes, f, indent=2)
        
        logging.info(f"Merged CWEs: {len(existing_cwes)} existing + {len(pip_audit_mapped_cwes)} from pip-audit = {len(merged_cwes)} total")
        
    except Exception as e:
        logging.error(f"Error merging pip-audit CWEs: {e}")

def main_function():
    logging.info("=== Starting main_function ===")
    
    logging.info("Step 1: Installing virtual environment")
    installVenv()
    logging.info("Step 1 completed: installVenv()")
    
    logging.info("Step 2: Creating virtual environment")
    createVenv()
    logging.info("Step 2 completed: createVenv()")
    
    logging.info("Step 3: Activating virtual environment")
    activateVenv()
    logging.info("Step 3 completed: activateVenv()")
    
    # Modified package installation with individual error handling
    logging.info("Step 4: Installing requirements with individual error handling")
    installation_results = installRequirements()
    logging.info(f"Step 4 completed: installRequirements() - {len(installation_results)} packages processed")
    
    logging.info("Step 5: Listing installed packages")
    listInstalledPackages()
    logging.info("Step 5 completed: listInstalledPackages()")
    
    logging.info("Step 6: Listing all dependencies")
    listAllDependencies()
    logging.info("Step 6 completed: listAllDependencies()")
    
    # New pip-audit functionality
    try:
        logging.info("=== Starting pip-audit vulnerability analysis ===")
        logging.info("Step 7: Running pip-audit")
        pip_path = "venv/bin/pip"
        subprocess.run([pip_path, "install", "pip-audit"], check=True)
        audit_output = runPipAudit()
        logging.info("Step 7 completed: runPipAudit()")
        
        if audit_output:
            # Parse audit results
            logging.info("Step 8: Parsing pip-audit output")
            audit_vulnerabilities = parsePipAuditOutput(audit_output)
            logging.info(f"Step 8 completed: parsePipAuditOutput() - found {len(audit_vulnerabilities)} vulnerabilities")
            
            # Match vulnerabilities to installed packages
            logging.info("Step 9: Matching audit results to installation")
            matched_vulnerabilities = matchAuditResultsToInstallation(installation_results, audit_vulnerabilities)
            logging.info(f"Step 9 completed: matchAuditResultsToInstallation() - matched {len(matched_vulnerabilities)} vulnerabilities")
            
            # Generate output files
            logging.info("Step 10: Generating CVE list")
            cve_list = generateCVEList(matched_vulnerabilities)
            logging.info(f"Step 10 completed: generateCVEList() - generated {len(cve_list)} CVEs")
            
            logging.info("Step 11: Generating package report")
            package_report = generatePackageReport(matched_vulnerabilities)
            logging.info("Step 11 completed: generatePackageReport()")
            
            # Write output files
            logging.info("Step 12: Writing output files")
            if writeOutputFiles(cve_list, package_report):
                logging.info("Step 12 completed: writeOutputFiles() - SUCCESS")
                logging.info("Pip-audit analysis completed successfully")
            else:
                logging.warning("Step 12 completed: writeOutputFiles() - FAILED")
                logging.warning("Pip-audit analysis completed but output file writing failed")
        else:
            logging.warning("Pip-audit execution failed, generating empty reports")
            # Generate empty reports for failed audit
            logging.info("Generating empty CVE list and package report")
            empty_cve_list = []
            empty_package_report = generatePackageReport([])
            writeOutputFiles(empty_cve_list, empty_package_report)
            logging.info("Empty reports generated successfully")
            
    except Exception as e:
        logging.error(f"Error during pip-audit analysis: {str(e)}")
        # Continue with rest of analysis even if pip-audit fails
        try:
            logging.info("Attempting to generate fallback empty reports")
            empty_cve_list = []
            empty_package_report = generatePackageReport([])
            writeOutputFiles(empty_cve_list, empty_package_report)
            logging.info("Generated empty audit reports due to pip-audit failure")
        except Exception as report_error:
            logging.error(f"Failed to generate fallback reports: {str(report_error)}")
    
    # Continue with existing analysis pipeline
    logging.info("=== Starting existing analysis pipeline ===")
    
    logging.info("Step 13: Downloading dependencies")
    download_Dependencies()
    logging.info("Step 13 completed: download_Dependencies()")
    
    logging.info("Step 14: Copying STDLIB files")
    copySTDLibFiles()
    logging.info("Step 14 completed: copySTDLibFiles()")
    
    logging.info("Step 15: Running Bandit static analysis")
    runBandit()
    logging.info("Step 15 completed: runBandit()")
    
    logging.info("Step 16: Parsing Bandit output")
    parseBandit()
    logging.info("Step 16 completed: parseBandit()")
    
    logging.info("Step 17: Getting vulnerable functions")
    getVulnerableFunctions()
    logging.info("Step 17 completed: getVulnerableFunctions()")
    
    # Generate the dynamic call graph
    logging.info("=== Starting dynamic call graph generation ===")
    logging.info(f"Profile wrapper arguments: {sys.argv[1]}, {sys.argv[2]}")
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    
    logging.info("Step 18: Running profiler wrapper")
    profilerWrapper(sys.argv[1], sys.argv[2])
    logging.info("Step 18 completed: profilerWrapper()")
    
    # Parse the dynamic analysis results
    logging.info("Step 19: Getting files and function names from call graph")
    getFilesAndFunctionNamesFromCallGraph()
    logging.info("Step 19 completed: getFilesAndFunctionNamesFromCallGraph()")
    
    # Match the vulnerable functions with the dynamic analysis results
    logging.info("Step 20: Matching vulnerabilities to calls")
    matchVulnerableFunctionsToCalledFunctions()
    logging.info("Step 20 completed: matchVulnerableFunctionsToCalledFunctions()")
    
    # NEW: Map pip-audit CVEs to CWEs and merge with existing CWEs
    logging.info("=== Starting CVE to CWE mapping ===")
    try:
        # Read the CVE list generated earlier
        logging.info("Step 21: Reading CVE list from /shared/cve_list.json")
        with open('/shared/cve_list.json', 'r') as f:
            pip_audit_cves = json.load(f)
        logging.info(f"Step 21 completed: Read {len(pip_audit_cves)} CVEs from file")
        
        # Map CVEs to CWEs using BRON database
        logging.info("Step 22: Mapping CVEs to CWEs using BRON database")
        mapped_cwes = mapCVEsToCWEs(pip_audit_cves)
        logging.info(f"Step 22 completed: mapCVEsToCWEs() - mapped {len(mapped_cwes)} CWEs from pip-audit CVEs")
        
        # Store mapped CWEs for merging after prepareCWEList()
        global pip_audit_mapped_cwes
        pip_audit_mapped_cwes = mapped_cwes
        logging.info("Step 22.1: Stored mapped CWEs in global variable")
        
    except Exception as e:
        logging.error(f"Error in CVE to CWE mapping: {e}")
        pip_audit_mapped_cwes = []
        logging.info("Set pip_audit_mapped_cwes to empty list due to error")
    
    logging.info("Step 23: Preparing CWE list from Bandit results")
    prepareCWEList()
    logging.info("Step 23 completed: prepareCWEList()")
    
    # Merge pip-audit CWEs with existing CWEs
    try:
        mergeCWEsFromPipAudit()
    except Exception as e:
        logging.error(f"Error merging pip-audit CWEs: {e}")

if __name__ == "__main__":
    main_function()
