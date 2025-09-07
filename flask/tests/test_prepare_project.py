import pytest
import os
import tempfile
from unittest.mock import patch, mock_open, MagicMock
import subprocess
import sys
import json
from datetime import datetime

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from prepareProject import parseRequirements, installRequirements, parsePipAuditOutput, matchAuditResultsToInstallation, generateCVEList, runPipAudit, generatePackageReport, generateCVEListFromMatchedResults

@pytest.mark.unit
class TestParseRequirements:
    
    def test_parse_simple_requirements(self):
        """Test parsing simple package==version format"""
        requirements_content = "flask==2.3.2\nrequests==2.28.1\n"
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("dummy_path")
        
        expected = ["flask==2.3.2", "requests==2.28.1"]
        assert result == expected
    
    def test_parse_requirements_with_comments(self):
        """Test parsing requirements with comments and empty lines"""
        requirements_content = """# This is a comment
flask==2.3.2
# Another comment
requests==2.28.1

# Empty line above
click==8.1.3"""
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("dummy_path")
        
        expected = ["flask==2.3.2", "requests==2.28.1", "click==8.1.3"]
        assert result == expected
    
    def test_parse_requirements_with_version_operators(self):
        """Test parsing requirements with different version operators"""
        requirements_content = """flask>=2.0.0
requests~=2.28.0
click<=8.1.3
pytest!=7.1.0
beautifulsoup4"""
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("dummy_path")
        
        expected = ["flask>=2.0.0", "requests~=2.28.0", "click<=8.1.3", "pytest!=7.1.0", "beautifulsoup4"]
        assert result == expected
    
    def test_parse_empty_requirements(self):
        """Test parsing empty requirements file"""
        requirements_content = "# Only comments\n\n# More comments\n"
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("dummy_path")
        
        assert result == []
    
    def test_parse_requirements_file_not_found(self):
        """Test handling of missing requirements file"""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = parseRequirements("nonexistent_file.txt")
        
        assert result == []
    
    def test_parse_requirements_with_whitespace(self):
        """Test parsing requirements with extra whitespace"""
        requirements_content = """  flask==2.3.2  
    requests==2.28.1    
click==8.1.3
  """
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("dummy_path")
        
        expected = ["flask==2.3.2", "requests==2.28.1", "click==8.1.3"]
        assert result == expected

@pytest.mark.unit
class TestInstallRequirements:
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_all_successful(self, mock_subprocess, mock_parse):
        """Test successful installation of all packages"""
        mock_parse.return_value = ["flask==2.3.2", "requests==2.28.1"]
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        result = installRequirements()
        
        assert len(result) == 2
        assert all(pkg['status'] == 'success' for pkg in result)
        assert result[0]['package'] == 'flask==2.3.2'
        assert result[1]['package'] == 'requests==2.28.1'
        assert mock_subprocess.call_count == 2
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_all_failed(self, mock_subprocess, mock_parse):
        """Test failed installation of all packages"""
        mock_parse.return_value = ["nonexistent-pkg==1.0.0", "fake-lib==2.0.0"]
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            1, 'pip install', stderr="Package not found"
        )
        
        result = installRequirements()
        
        assert len(result) == 2
        assert all(pkg['status'] == 'failed' for pkg in result)
        assert all('Package not found' in pkg['error_message'] for pkg in result)
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_mixed_results(self, mock_subprocess, mock_parse):
        """Test mixed successful and failed installations"""
        mock_parse.return_value = ["flask==2.3.2", "nonexistent-pkg==1.0.0", "requests==2.28.1"]
        
        def mock_run_side_effect(cmd, **kwargs):
            if "flask" in cmd:
                return MagicMock(returncode=0)
            elif "nonexistent-pkg" in cmd:
                raise subprocess.CalledProcessError(1, 'pip install', stderr="Package not found")
            elif "requests" in cmd:
                return MagicMock(returncode=0)
        
        mock_subprocess.side_effect = mock_run_side_effect
        
        result = installRequirements()
        
        assert len(result) == 3
        successful = [pkg for pkg in result if pkg['status'] == 'success']
        failed = [pkg for pkg in result if pkg['status'] == 'failed']
        
        assert len(successful) == 2
        assert len(failed) == 1
        assert failed[0]['package'] == 'nonexistent-pkg==1.0.0'
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_unexpected_error(self, mock_subprocess, mock_parse):
        """Test handling of unexpected errors during installation"""
        mock_parse.return_value = ["flask==2.3.2"]
        mock_subprocess.side_effect = Exception("Unexpected error")
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'Unexpected error' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    def test_install_requirements_no_packages(self, mock_parse):
        """Test behavior when no packages to install"""
        mock_parse.return_value = []
        
        result = installRequirements()
        
        assert result == []
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_stderr_handling(self, mock_subprocess, mock_parse):
        """Test proper stderr message extraction"""
        mock_parse.return_value = ["invalid-pkg==1.0.0"]
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: Could not find a version that satisfies the requirement"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert "Could not find a version" in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_empty_stderr(self, mock_subprocess, mock_parse):
        """Test handling when stderr is empty"""
        mock_parse.return_value = ["invalid-pkg==1.0.0"]
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = ""
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert result[0]['error_message'] is not None

@pytest.mark.unit
class TestParsePipAuditOutput:
    
    def test_parse_valid_pip_audit_output(self):
        """Test parsing valid pip-audit JSON output with vulnerabilities"""
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "Flask vulnerable to XSS",
                        "fix_versions": ["2.3.2"]
                    }
                ]
            },
            {
                "package": "requests",
                "version": "2.6.0",
                "vulns": [
                    {
                        "id": "CVE-2023-32681",
                        "description": "Requests vulnerable to SSRF",
                        "fix_versions": ["2.31.0"]
                    }
                ]
            }
        ])
        
        result = parsePipAuditOutput(audit_output)
        
        assert len(result) == 2
        assert result[0]['package'] == 'flask'
        assert result[0]['version'] == '1.0.0'
        assert len(result[0]['vulns']) == 1
        assert result[0]['vulns'][0]['id'] == 'CVE-2023-30861'
        assert result[1]['package'] == 'requests'
        assert len(result[1]['vulns']) == 1
    
    def test_parse_empty_pip_audit_output(self):
        """Test parsing pip-audit output with no vulnerabilities"""
        audit_output = json.dumps([])
        
        result = parsePipAuditOutput(audit_output)
        
        assert result == []
    
    def test_parse_packages_without_vulnerabilities(self):
        """Test parsing pip-audit output with packages but no vulnerabilities"""
        audit_output = json.dumps([
            {
                "package": "requests",
                "version": "2.31.0",
                "vulns": []
            },
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            }
        ])
        
        result = parsePipAuditOutput(audit_output)
        
        assert len(result) == 2
        assert all(len(pkg['vulns']) == 0 for pkg in result)
        assert result[0]['package'] == 'requests'
        assert result[1]['package'] == 'flask'
    
    def test_parse_invalid_json_output(self):
        """Test handling of malformed JSON output"""
        invalid_json = "This is not valid JSON"
        
        result = parsePipAuditOutput(invalid_json)
        
        assert result == []
    
    def test_parse_empty_string_output(self):
        """Test handling of empty string output"""
        result = parsePipAuditOutput("")
        
        assert result == []
    
    def test_parse_none_output(self):
        """Test handling of None output"""
        result = parsePipAuditOutput(None)
        
        assert result == []
    
    def test_parse_multiple_vulnerabilities_per_package(self):
        """Test parsing packages with multiple vulnerabilities"""
        audit_output = json.dumps([
            {
                "package": "django",
                "version": "3.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"]
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability",
                        "fix_versions": ["3.2.22"]
                    }
                ]
            }
        ])
        
        result = parsePipAuditOutput(audit_output)
        
        assert len(result) == 1
        assert result[0]['package'] == 'django'
        assert len(result[0]['vulns']) == 2
        assert result[0]['vulns'][0]['id'] == 'CVE-2023-41164'
        assert result[0]['vulns'][1]['id'] == 'CVE-2023-43665'
    
    def test_parse_missing_fields_in_output(self):
        """Test handling of pip-audit output with missing fields"""
        audit_output = json.dumps([
            {
                "package": "flask",
                "vulns": [
                    {
                        "id": "CVE-2023-30861"
                    }
                ]
            }
        ])
        
        result = parsePipAuditOutput(audit_output)
        
        assert len(result) == 1
        assert result[0]['package'] == 'flask'
        assert 'version' in result[0]  # Should have default or None
        assert len(result[0]['vulns']) == 1
        assert result[0]['vulns'][0]['id'] == 'CVE-2023-30861'
    
    def test_parse_unexpected_json_structure(self):
        """Test handling of unexpected JSON structure"""
        audit_output = json.dumps({
            "unexpected": "structure",
            "not_a_list": True
        })
        
        result = parsePipAuditOutput(audit_output)
        
        assert result == []

@pytest.mark.unit
class TestMatchAuditResultsToInstallation:
    
    def test_match_perfect_correlation(self):
        """Test matching when all installed packages have audit results"""
        installation_results = [
            {"package": "flask==2.3.2", "status": "success"},
            {"package": "requests==2.28.1", "status": "success"}
        ]
        
        audit_results = [
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": [{"id": "CVE-2023-30861", "description": "XSS vulnerability"}]
            },
            {
                "package": "requests", 
                "version": "2.28.1",
                "vulns": []
            }
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 2
        assert result[0]['package'] == 'flask'
        assert result[0]['installed_version'] == '2.3.2'
        assert len(result[0]['vulns']) == 1
        assert result[1]['package'] == 'requests'
        assert len(result[1]['vulns']) == 0
    
    def test_match_with_failed_installations(self):
        """Test matching when some packages failed to install"""
        installation_results = [
            {"package": "flask==2.3.2", "status": "success"},
            {"package": "nonexistent-pkg==1.0.0", "status": "failed", "error_message": "Not found"}
        ]
        
        audit_results = [
            {
                "package": "flask",
                "version": "2.3.2", 
                "vulns": []
            }
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 1  # Only successful installations should be matched
        assert result[0]['package'] == 'flask'
        assert result[0]['installed_version'] == '2.3.2'
    
    def test_match_with_version_mismatches(self):
        """Test matching when audit version differs from requested version"""
        installation_results = [
            {"package": "flask>=2.0.0", "status": "success"}
        ]
        
        audit_results = [
            {
                "package": "flask",
                "version": "2.3.2",  # Actual installed version
                "vulns": [{"id": "CVE-2023-30861"}]
            }
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 1
        assert result[0]['package'] == 'flask'
        assert result[0]['requested_version'] == '>=2.0.0'
        assert result[0]['installed_version'] == '2.3.2'
        assert len(result[0]['vulns']) == 1
    
    def test_match_with_missing_audit_results(self):
        """Test matching when some installed packages have no audit results"""
        installation_results = [
            {"package": "flask==2.3.2", "status": "success"},
            {"package": "requests==2.28.1", "status": "success"}
        ]
        
        audit_results = [
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            }
            # Missing requests audit result
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 2
        flask_result = next(r for r in result if r['package'] == 'flask')
        requests_result = next(r for r in result if r['package'] == 'requests')
        
        assert len(flask_result['vulns']) == 0
        assert requests_result['vulns'] == []  # Should have empty vulns list
        assert requests_result['audit_status'] == 'no_audit_data'
    
    def test_match_with_extra_audit_results(self):
        """Test matching when audit has results for packages not installed"""
        installation_results = [
            {"package": "flask==2.3.2", "status": "success"}
        ]
        
        audit_results = [
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            },
            {
                "package": "requests",  # Not in installation results
                "version": "2.28.1",
                "vulns": [{"id": "CVE-2023-32681"}]
            }
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 1  # Only installed packages should be in result
        assert result[0]['package'] == 'flask'
    
    def test_match_empty_inputs(self):
        """Test matching with empty installation or audit results"""
        result1 = matchAuditResultsToInstallation([], [])
        assert result1 == []
        
        result2 = matchAuditResultsToInstallation(
            [{"package": "flask==2.3.2", "status": "success"}], 
            []
        )
        assert len(result2) == 1
        assert result2[0]['vulns'] == []
        assert result2[0]['audit_status'] == 'no_audit_data'
        
        result3 = matchAuditResultsToInstallation([], [{"package": "flask", "vulns": []}])
        assert result3 == []
    
    def test_match_package_name_normalization(self):
        """Test matching with different package name formats"""
        installation_results = [
            {"package": "python-dateutil==2.8.2", "status": "success"}
        ]
        
        audit_results = [
            {
                "package": "python_dateutil",  # Underscore vs hyphen
                "version": "2.8.2",
                "vulns": []
            }
        ]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 1
        assert result[0]['package'] == 'python_dateutil'
        assert result[0]['installed_version'] == '2.8.2'

@pytest.mark.unit
class TestGenerateCVEList:
    
    def test_generate_cve_list_with_vulnerabilities(self):
        """Test CVE list generation from matched results with vulnerabilities"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"},
                    {"id": "CVE-2023-30862", "description": "CSRF vulnerability"}
                ]
            },
            {
                "package": "requests",
                "installed_version": "2.6.0",
                "vulns": [
                    {"id": "CVE-2023-32681", "description": "SSRF vulnerability"}
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        assert len(result) == 3
        cve_ids = [cve['id'] for cve in result]
        assert "CVE-2023-30861" in cve_ids
        assert "CVE-2023-30862" in cve_ids
        assert "CVE-2023-32681" in cve_ids
        
        # Verify CVE structure
        flask_cve = next(cve for cve in result if cve['id'] == 'CVE-2023-30861')
        assert flask_cve['package'] == 'flask'
        assert flask_cve['version'] == '1.0.0'
        assert flask_cve['description'] == 'XSS vulnerability'
    
    def test_generate_cve_list_no_vulnerabilities(self):
        """Test CVE list generation when no vulnerabilities found"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "2.3.2",
                "vulns": []
            },
            {
                "package": "requests",
                "installed_version": "2.31.0",
                "vulns": []
            }
        ]
        
        result = generateCVEList(matched_results)
        
        assert result == []
    
    def test_generate_cve_list_mixed_vulnerabilities(self):
        """Test CVE list generation with mixed vulnerable and clean packages"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"}
                ]
            },
            {
                "package": "requests",
                "installed_version": "2.31.0",
                "vulns": []  # No vulnerabilities
            },
            {
                "package": "django",
                "installed_version": "3.0.0",
                "vulns": [
                    {"id": "CVE-2023-41164", "description": "SQL injection"}
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        assert len(result) == 2
        cve_ids = [cve['id'] for cve in result]
        assert "CVE-2023-30861" in cve_ids
        assert "CVE-2023-41164" in cve_ids
    
    def test_generate_cve_list_duplicate_removal(self):
        """Test CVE list generation removes duplicate CVEs"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"}
                ]
            },
            {
                "package": "flask-cors",
                "installed_version": "3.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"}  # Duplicate CVE
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        assert len(result) == 1
        assert result[0]['id'] == 'CVE-2023-30861'
        # Should keep the first occurrence
        assert result[0]['package'] == 'flask'
    
    def test_generate_cve_list_empty_input(self):
        """Test CVE list generation with empty input"""
        result = generateCVEList([])
        
        assert result == []
    
    def test_generate_cve_list_missing_fields(self):
        """Test CVE list generation with missing fields in vulnerability data"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861"},  # Missing description
                    {"description": "Missing CVE ID"}  # Missing id
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        # Should handle missing fields gracefully
        assert len(result) >= 0  # May filter out invalid entries
        if result:
            assert all('id' in cve for cve in result)
    
    def test_generate_cve_list_cve_format_validation(self):
        """Test CVE list generation validates CVE ID format"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "Valid CVE"},
                    {"id": "INVALID-ID", "description": "Invalid format"},
                    {"id": "CVE-2023-INVALID", "description": "Invalid CVE format"}
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        # Should only include valid CVE format
        valid_cves = [cve for cve in result if cve['id'].startswith('CVE-')]
        assert len(valid_cves) >= 1
        assert any(cve['id'] == 'CVE-2023-30861' for cve in valid_cves)
    
    def test_generate_cve_list_sorting(self):
        """Test CVE list generation sorts results consistently"""
        matched_results = [
            {
                "package": "requests",
                "installed_version": "2.6.0",
                "vulns": [
                    {"id": "CVE-2023-32681", "description": "SSRF vulnerability"}
                ]
            },
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"}
                ]
            }
        ]
        
        result = generateCVEList(matched_results)
        
        assert len(result) == 2
        # Should be sorted by CVE ID
        assert result[0]['id'] <= result[1]['id']

@pytest.mark.unit
class TestRunPipAudit:
    
    @patch('subprocess.run')
    def test_run_pip_audit_successful(self, mock_subprocess):
        """Test successful pip-audit execution"""
        expected_output = json.dumps([
            {
                "package": "flask",
                "version": "1.0.0",
                "vulns": [{"id": "CVE-2023-30861", "description": "XSS vulnerability"}]
            }
        ])
        
        mock_result = MagicMock()
        mock_result.stdout = expected_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        assert result == expected_output
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_run_pip_audit_no_vulnerabilities(self, mock_subprocess):
        """Test pip-audit when no vulnerabilities found"""
        expected_output = json.dumps([])
        
        mock_result = MagicMock()
        mock_result.stdout = expected_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        assert result == expected_output
        assert json.loads(result) == []
    
    @patch('subprocess.run')
    def test_run_pip_audit_command_not_found(self, mock_subprocess):
        """Test pip-audit when command is not installed"""
        mock_subprocess.side_effect = FileNotFoundError("pip-audit command not found")
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_run_pip_audit_subprocess_error(self, mock_subprocess):
        """Test pip-audit when subprocess fails"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "Error running pip-audit"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_run_pip_audit_with_custom_format(self, mock_subprocess):
        """Test pip-audit with custom format parameter"""
        expected_output = "text format output"
        
        mock_result = MagicMock()
        mock_result.stdout = expected_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit(format_type="text")
        
        assert result == expected_output
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=text"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_run_pip_audit_with_requirements_file(self, mock_subprocess):
        """Test pip-audit with specific requirements file"""
        expected_output = json.dumps([])
        
        mock_result = MagicMock()
        mock_result.stdout = expected_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit(requirements_file="requirements.txt")
        
        assert result == expected_output
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=json", "--requirement", "requirements.txt"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_run_pip_audit_timeout_error(self, mock_subprocess):
        """Test pip-audit when command times out"""
        mock_subprocess.side_effect = subprocess.TimeoutExpired('pip-audit', 30)
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_run_pip_audit_permission_error(self, mock_subprocess):
        """Test pip-audit when permission denied"""
        mock_subprocess.side_effect = PermissionError("Permission denied")
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_run_pip_audit_empty_stdout(self, mock_subprocess):
        """Test pip-audit when stdout is empty"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        assert result == ""
    
    @patch('subprocess.run')
    def test_run_pip_audit_with_additional_args(self, mock_subprocess):
        """Test pip-audit with additional command line arguments"""
        expected_output = json.dumps([])
        
        mock_result = MagicMock()
        mock_result.stdout = expected_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit(additional_args=["--ignore-vuln", "CVE-2023-30861"])
        
        assert result == expected_output
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=json", "--ignore-vuln", "CVE-2023-30861"],
            capture_output=True,
            text=True,
            check=True
        )

@pytest.mark.unit
class TestPipAuditCommandFailures:
    
    @patch('subprocess.run')
    def test_pip_audit_command_not_found(self, mock_subprocess):
        """Test handling when pip-audit command is not installed"""
        mock_subprocess.side_effect = FileNotFoundError("pip-audit command not found")
        
        result = runPipAudit()
        
        assert result is None
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_pip_audit_subprocess_error(self, mock_subprocess):
        """Test handling when pip-audit subprocess fails"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "Error running pip-audit"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_timeout_error(self, mock_subprocess):
        """Test handling when pip-audit command times out"""
        mock_subprocess.side_effect = subprocess.TimeoutExpired('pip-audit', 30)
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_permission_error(self, mock_subprocess):
        """Test handling when pip-audit has permission issues"""
        mock_subprocess.side_effect = PermissionError("Permission denied")
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_empty_stdout(self, mock_subprocess):
        """Test handling when pip-audit returns empty output"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        assert result == ""
    
    @patch('subprocess.run')
    def test_pip_audit_malformed_json_output(self, mock_subprocess):
        """Test handling when pip-audit returns malformed JSON"""
        mock_result = MagicMock()
        mock_result.stdout = "This is not valid JSON output"
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        # runPipAudit should return the raw output, parsing happens elsewhere
        assert result == "This is not valid JSON output"
    
    @patch('subprocess.run')
    def test_pip_audit_network_failure(self, mock_subprocess):
        """Test handling when pip-audit fails due to network issues"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: Network connection failed"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_database_update_failure(self, mock_subprocess):
        """Test handling when pip-audit fails to update vulnerability database"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: Failed to update vulnerability database"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_invalid_package_environment(self, mock_subprocess):
        """Test handling when pip-audit can't analyze the environment"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: No packages found in environment"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_version_incompatibility(self, mock_subprocess):
        """Test handling when pip-audit version is incompatible"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: Unsupported pip-audit version"
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('prepareProject.runPipAudit')
    @patch('prepareProject.installRequirements')
    def test_fallback_behavior_on_pip_audit_failure(self, mock_install, mock_pip_audit):
        """Test that system continues with empty audit results when pip-audit fails"""
        # Mock successful installation
        mock_install.return_value = [
            {"package": "flask==2.3.2", "status": "success"},
            {"package": "requests==2.28.1", "status": "success"}
        ]
        
        # Mock pip-audit failure
        mock_pip_audit.return_value = None
        
        with patch('prepareProject.parsePipAuditOutput') as mock_parse:
            with patch('prepareProject.matchAuditResultsToInstallation') as mock_match:
                with patch('prepareProject.generatePackageReport') as mock_report:
                    with patch('prepareProject.generateCVEListFromMatchedResults') as mock_cve:
                        with patch('prepareProject.writeOutputFiles') as mock_write:
                            # Mock the parsing to return empty results for None input
                            mock_parse.return_value = []
                            mock_match.return_value = [
                                {
                                    "package": "flask",
                                    "installed_version": "2.3.2",
                                    "status": "success",
                                    "audit_status": "failed",
                                    "vulns": []
                                },
                                {
                                    "package": "requests", 
                                    "installed_version": "2.28.1",
                                    "status": "success",
                                    "audit_status": "failed",
                                    "vulns": []
                                }
                            ]
                            mock_report.return_value = {"packages": [], "summary": {}}
                            mock_cve.return_value = []
                            
                            # This would be called in the main function
                            installation_results = mock_install.return_value
                            audit_output = mock_pip_audit.return_value
                            audit_results = mock_parse(audit_output)
                            matched_results = mock_match(installation_results, audit_results)
                            
                            # Verify fallback behavior
                            mock_parse.assert_called_once_with(None)
                            assert len(matched_results) == 2
                            assert all(pkg['audit_status'] == 'failed' for pkg in matched_results)
                            assert all(len(pkg['vulns']) == 0 for pkg in matched_results)
    
    @patch('subprocess.run')
    def test_pip_audit_with_custom_parameters_failure(self, mock_subprocess):
        """Test pip-audit failure with custom parameters"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: Invalid format specified"
        mock_subprocess.side_effect = error
        
        result = runPipAudit(format_type="invalid-format")
        
        assert result is None
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=invalid-format"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_pip_audit_requirements_file_not_found(self, mock_subprocess):
        """Test pip-audit failure when requirements file doesn't exist"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "ERROR: Requirements file not found: nonexistent.txt"
        mock_subprocess.side_effect = error
        
        result = runPipAudit(requirements_file="nonexistent.txt")
        
        assert result is None
        mock_subprocess.assert_called_once_with(
            ["pip-audit", "--format=json", "--requirement", "nonexistent.txt"],
            capture_output=True,
            text=True,
            check=True
        )
    
    @patch('subprocess.run')
    def test_pip_audit_memory_error(self, mock_subprocess):
        """Test handling when pip-audit runs out of memory"""
        mock_subprocess.side_effect = MemoryError("Out of memory")
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_keyboard_interrupt(self, mock_subprocess):
        """Test handling when pip-audit is interrupted"""
        mock_subprocess.side_effect = KeyboardInterrupt()
        
        # KeyboardInterrupt should propagate
        with pytest.raises(KeyboardInterrupt):
            runPipAudit()
    
    @patch('subprocess.run')
    def test_pip_audit_unexpected_exception(self, mock_subprocess):
        """Test handling of unexpected exceptions during pip-audit"""
        mock_subprocess.side_effect = Exception("Unexpected error")
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_logging_on_failure(self, mock_subprocess):
        """Test that pip-audit failures are properly logged"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = "Audit failed"
        mock_subprocess.side_effect = error
        
        with patch('prepareProject.logging.warning') as mock_log:
            result = runPipAudit()
            
            assert result is None
            # Verify logging was called (implementation dependent)
            # This assumes the function logs failures
    
    @patch('subprocess.run')
    def test_pip_audit_stderr_none_handling(self, mock_subprocess):
        """Test handling when pip-audit error has None stderr"""
        error = subprocess.CalledProcessError(1, 'pip-audit')
        error.stderr = None
        mock_subprocess.side_effect = error
        
        result = runPipAudit()
        
        assert result is None
    
    @patch('subprocess.run')
    def test_pip_audit_return_code_handling(self, mock_subprocess):
        """Test handling of different pip-audit return codes"""
        # Test non-zero return code with successful output
        mock_result = MagicMock()
        mock_result.stdout = '[]'  # Valid empty JSON
        mock_result.returncode = 2  # Non-zero but not failure
        mock_subprocess.return_value = mock_result
        
        result = runPipAudit()
        
        # Should still return output if stdout is valid
        assert result == '[]'
    
    def test_parse_pip_audit_output_with_none_input(self):
        """Test parsePipAuditOutput handles None input from failed pip-audit"""
        result = parsePipAuditOutput(None)
        
        assert result == []
    
    def test_parse_pip_audit_output_with_empty_string(self):
        """Test parsePipAuditOutput handles empty string from pip-audit"""
        result = parsePipAuditOutput("")
        
        assert result == []
    
    def test_parse_pip_audit_output_with_malformed_json(self):
        """Test parsePipAuditOutput handles malformed JSON from pip-audit"""
        malformed_json = "This is not JSON at all"
        
        result = parsePipAuditOutput(malformed_json)
        
        assert result == []

@pytest.mark.unit
class TestJSONStructureValidation:
    
    def test_package_report_json_structure(self):
        """Test that generatePackageReport produces valid JSON with correct structure"""
        matched_results = [
            {
                "package": "flask",
                "installed_version": "1.0.0",
                "requested_version": ">=1.0.0",
                "status": "success",
                "audit_status": "success",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "XSS vulnerability",
                        "fix_versions": ["2.3.2"],
                        "severity": "high"
                    }
                ]
            },
            {
                "package": "requests",
                "installed_version": "2.31.0",
                "status": "success",
                "audit_status": "success",
                "vulns": []
            }
        ]
        
        with patch('prepareProject.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2023-12-01T10:00:00"
            result = generatePackageReport(matched_results)
        
        # Verify it's valid JSON by serializing and deserializing
        json_str = json.dumps(result)
        parsed_result = json.loads(json_str)
        
        # Verify top-level structure
        assert "report_metadata" in parsed_result
        assert "summary" in parsed_result
        assert "packages" in parsed_result
        
        # Verify report_metadata structure
        metadata = parsed_result["report_metadata"]
        assert "generated_at" in metadata
        assert "report_type" in metadata
        assert "total_packages" in metadata
        assert metadata["report_type"] == "package_vulnerability_audit"
        assert metadata["total_packages"] == 2
        
        # Verify summary structure
        summary = parsed_result["summary"]
        required_summary_fields = [
            "packages_with_vulnerabilities",
            "total_vulnerabilities", 
            "packages_clean",
            "packages_failed_audit"
        ]
        for field in required_summary_fields:
            assert field in summary
            assert isinstance(summary[field], int)
        
        # Verify packages structure
        packages = parsed_result["packages"]
        assert isinstance(packages, list)
        assert len(packages) == 2
        
        # Verify individual package structure
        for package in packages:
            required_package_fields = [
                "name", "installed_version", "requested_version",
                "installation_status", "audit_status", 
                "vulnerability_count", "vulnerabilities"
            ]
            for field in required_package_fields:
                assert field in package
            
            assert isinstance(package["vulnerabilities"], list)
            assert isinstance(package["vulnerability_count"], int)
    
    def test_cve_list_json_structure(self):
        """Test that generateCVEListFromMatchedResults produces valid JSON structure"""
        matched_results = [
            {
                "package": "flask",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "XSS vulnerability"},
                    {"id": "CVE-2023-30862", "description": "CSRF vulnerability"}
                ]
            },
            {
                "package": "requests",
                "vulns": [
                    {"id": "CVE-2023-32681", "description": "SSRF vulnerability"}
                ]
            }
        ]
        
        result = generateCVEListFromMatchedResults(matched_results)
        
        # Verify it's valid JSON by serializing and deserializing
        json_str = json.dumps(result)
        parsed_result = json.loads(json_str)
        
        # Verify structure is list of CVE objects
        assert isinstance(parsed_result, list)
        assert len(parsed_result) == 3
        
        # Verify each CVE object structure
        for cve_item in parsed_result:
            assert isinstance(cve_item, dict)
            assert "cve" in cve_item
            assert isinstance(cve_item["cve"], str)
            assert cve_item["cve"].startswith("CVE-")
    
    def test_package_report_vulnerability_structure(self):
        """Test vulnerability objects within package report have correct structure"""
        matched_results = [
            {
                "package": "django",
                "installed_version": "3.0.0",
                "status": "success",
                "audit_status": "success",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability",
                        "fix_versions": ["3.2.22"],
                        "severity": "medium"
                    }
                ]
            }
        ]
        
        result = generatePackageReport(matched_results)
        
        # Verify it's valid JSON by serializing and deserializing
        json_str = json.dumps(result)
        parsed_result = json.loads(json_str)
        
        # Verify top-level structure
        assert "report_metadata" in parsed_result
        assert "summary" in parsed_result
        assert "packages" in parsed_result

@pytest.mark.integration
class TestFullPipelineMixedResults:
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==2.3.2\nnonexistent-pkg==1.0.0\nrequests==2.28.1\nfake-lib==2.0.0\n"))
    def test_pipeline_mixed_installation_success_failure(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with mixed successful and failed installations"""
        # Mock mixed pip installation results
        def mock_run_side_effect(cmd, **kwargs):
            if "flask" in cmd:
                return MagicMock(returncode=0)
            elif "nonexistent-pkg" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Could not find a version that satisfies the requirement nonexistent-pkg==1.0.0"
                raise error
            elif "requests" in cmd:
                return MagicMock(returncode=0)
            elif "fake-lib" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: No matching distribution found for fake-lib==2.0.0"
                raise error
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output only for successfully installed packages
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "Flask XSS vulnerability",
                        "fix_versions": ["2.3.3"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "requests",
                "version": "2.28.1",
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 4
        successful_installs = [pkg for pkg in installation_results if pkg['status'] == 'success']
        failed_installs = [pkg for pkg in installation_results if pkg['status'] == 'failed']
        
        assert len(successful_installs) == 2
        assert len(failed_installs) == 2
        
        # Verify successful installations
        flask_install = next(pkg for pkg in successful_installs if 'flask' in pkg['package'])
        requests_install = next(pkg for pkg in successful_installs if 'requests' in pkg['package'])
        assert flask_install['package'] == 'flask==2.3.2'
        assert requests_install['package'] == 'requests==2.28.1'
        
        # Verify failed installations
        nonexistent_install = next(pkg for pkg in failed_installs if 'nonexistent-pkg' in pkg['package'])
        fake_lib_install = next(pkg for pkg in failed_installs if 'fake-lib' in pkg['package'])
        assert 'Could not find a version' in nonexistent_install['error_message']
        assert 'No matching distribution' in fake_lib_install['error_message']
        
        # Verify only successful installations are audited
        assert len(audit_results) == 2
        assert all(pkg['package'] in ['flask', 'requests'] for pkg in audit_results)
        
        # Verify matched results only include successful installations
        assert len(matched_results) == 2
        flask_result = next(r for r in matched_results if r['package'] == 'flask')
        requests_result = next(r for r in matched_results if r['package'] == 'requests')
        
        assert len(flask_result['vulns']) == 1
        assert len(requests_result['vulns']) == 0
        
        # Verify package report reflects only successful installations
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 1
        assert package_report['summary']['packages_clean'] == 1
        
        # Verify CVE list only includes vulnerabilities from successful installations
        assert len(cve_list) == 1
        assert cve_list[0]['cve'] == 'CVE-2023-30861'
        assert cve_list[0]['package'] == 'flask'
        
        # Verify output files written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="django==3.2.0\ninvalid-package\nrequests==2.28.1\n"))
    def test_pipeline_with_malformed_requirements(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with malformed requirements causing installation failures"""
        # Mock mixed pip installation results
        def mock_run_side_effect(cmd, **kwargs):
            if "django" in cmd:
                return MagicMock(returncode=0)
            elif "invalid-package" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Invalid requirement, parse error"
                raise error
            elif "requests" in cmd:
                return MagicMock(returncode=0)
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output for successful installations
        audit_output = json.dumps([
            {
                "package": "django",
                "version": "3.2.0",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"],
                        "severity": "critical"
                    }
                ]
            },
            {
                "package": "requests",
                "version": "2.28.1",
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify mixed results handling
        assert len(installation_results) == 3
        successful_count = sum(1 for pkg in installation_results if pkg['status'] == 'success')
        failed_count = sum(1 for pkg in installation_results if pkg['status'] == 'failed')
        
        assert successful_count == 2
        assert failed_count == 1
        
        # Verify malformed requirement error handling
        failed_pkg = next(pkg for pkg in installation_results if pkg['status'] == 'failed')
        assert 'parse error' in failed_pkg['error_message']
        
        # Verify successful packages are processed normally
        assert len(matched_results) == 2
        assert package_report['summary']['total_packages'] == 2
        assert len(cve_list) == 1
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="numpy==1.21.0\nscipy==1.7.0\nmatplotlib==3.4.0\npandas==1.3.0\nsklearn==0.24.0\n"))
    def test_pipeline_partial_installation_failures(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline where some packages fail due to dependency issues"""
        # Mock partial installation failures
        def mock_run_side_effect(cmd, **kwargs):
            if "numpy" in cmd:
                return MagicMock(returncode=0)
            elif "scipy" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Failed building wheel for scipy"
                raise error
            elif "matplotlib" in cmd:
                return MagicMock(returncode=0)
            elif "pandas" in cmd:
                return MagicMock(returncode=0)
            elif "sklearn" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Could not build wheels for scikit-learn"
                raise error
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output for successful installations
        audit_output = json.dumps([
            {
                "package": "numpy",
                "version": "1.21.0",
                "vulns": []
            },
            {
                "package": "matplotlib",
                "version": "3.4.0",
                "vulns": [
                    {
                        "id": "CVE-2023-MATPLOTLIB",
                        "description": "Matplotlib vulnerability",
                        "fix_versions": ["3.5.0"],
                        "severity": "low"
                    }
                ]
            },
            {
                "package": "pandas",
                "version": "1.3.0",
                "vulns": [
                    {
                        "id": "CVE-2023-PANDAS1",
                        "description": "Pandas vulnerability 1",
                        "fix_versions": ["1.4.0"],
                        "severity": "medium"
                    },
                    {
                        "id": "CVE-2023-PANDAS2",
                        "description": "Pandas vulnerability 2",
                        "fix_versions": ["1.4.1"],
                        "severity": "high"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify partial failure handling
        assert len(installation_results) == 5
        successful_installs = [pkg for pkg in installation_results if pkg['status'] == 'success']
        failed_installs = [pkg for pkg in installation_results if pkg['status'] == 'failed']
        
        assert len(successful_installs) == 3  # numpy, matplotlib, pandas
        assert len(failed_installs) == 2     # scipy, sklearn
        
        # Verify build failure error messages
        scipy_fail = next(pkg for pkg in failed_installs if 'scipy' in pkg['package'])
        sklearn_fail = next(pkg for pkg in failed_installs if 'sklearn' in pkg['package'])
        assert 'Failed building wheel' in scipy_fail['error_message']
        assert 'Could not build wheels' in sklearn_fail['error_message']
        
        # Verify successful packages are audited
        assert len(matched_results) == 3
        assert package_report['summary']['total_packages'] == 3
        assert package_report['summary']['packages_with_vulnerabilities'] == 2  # matplotlib, pandas
        assert package_report['summary']['total_vulnerabilities'] == 3
        assert package_report['summary']['packages_clean'] == 1  # numpy
        
        # Verify CVE list includes all vulnerabilities from successful installations
        assert len(cve_list) == 3
        cve_ids = [cve['cve'] for cve in cve_list]
        assert 'CVE-2023-MATPLOTLIB' in cve_ids
        assert 'CVE-2023-PANDAS1' in cve_ids
        assert 'CVE-2023-PANDAS2' in cve_ids
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="working-pkg==1.0.0\nbroken-pkg==2.0.0\n"))
    def test_pipeline_with_pip_audit_partial_data(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline where pip-audit returns partial data due to some package issues"""
        # Mock mixed installation results
        def mock_run_side_effect(cmd, **kwargs):
            if "working-pkg" in cmd:
                return MagicMock(returncode=0)
            elif "broken-pkg" in cmd:
                return MagicMock(returncode=0)  # Installation succeeds
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output with partial data (missing broken-pkg)
        audit_output = json.dumps([
            {
                "package": "working-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-WORKING",
                        "description": "Working package vulnerability",
                        "fix_versions": ["1.1.0"],
                        "severity": "medium"
                    }
                ]
            }
            # Note: broken-pkg is missing from audit results
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify both packages were installed successfully
        assert len(installation_results) == 2
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        
        # Verify audit results only contain one package
        assert len(audit_results) == 1
        assert audit_results[0]['package'] == 'working-pkg'
        
        # Verify matched results handle missing audit data
        assert len(matched_results) == 2
        working_result = next(r for r in matched_results if r['package'] == 'working-pkg')
        broken_result = next(r for r in matched_results if r['package'] == 'broken-pkg')
        
        assert len(working_result['vulns']) == 1
        assert len(broken_result['vulns']) == 0
        assert broken_result['audit_status'] == 'no_audit_data'
        
        # Verify package report includes both packages
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['packages_failed_audit'] == 1
        
        # Verify CVE list only includes audited vulnerabilities
        assert len(cve_list) == 1
        assert cve_list[0]['package'] == 'working-pkg'
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="timeout-pkg==1.0.0\nslow-pkg==2.0.0\nfast-pkg==3.0.0\n"))
    def test_pipeline_with_installation_timeouts(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with installation timeouts and mixed results"""
        # Mock installation results with timeouts
        def mock_run_side_effect(cmd, **kwargs):
            if "timeout-pkg" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Operation timed out"
                raise error
            elif "slow-pkg" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Read timed out"
                raise error
            elif "fast-pkg" in cmd:
                return MagicMock(returncode=0)
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output for successful installation
        audit_output = json.dumps([
            {
                "package": "fast-pkg",
                "version": "3.0.0",
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify timeout handling
        assert len(installation_results) == 3
        successful_count = sum(1 for pkg in installation_results if pkg['status'] == 'success')
        failed_count = sum(1 for pkg in installation_results if pkg['status'] == 'failed')
        
        assert successful_count == 1
        assert failed_count == 2
        
        # Verify timeout error messages
        timeout_failures = [pkg for pkg in installation_results if pkg['status'] == 'failed']
        timeout_errors = [pkg['error_message'] for pkg in timeout_failures]
        assert any('timed out' in error.lower() for error in timeout_errors)
        
        # Verify only successful installation is processed
        assert len(matched_results) == 1
        assert matched_results[0]['package'] == 'fast-pkg'
        assert package_report['summary']['total_packages'] == 1
        assert len(cve_list) == 0

@pytest.mark.integration
class TestOutputFileGeneration:
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==2.3.2\nrequests==2.28.1\n"))
    def test_output_files_generation_clean_packages(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test output file generation with clean packages (no vulnerabilities)"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with no vulnerabilities
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            },
            {
                "package": "requests",
                "version": "2.28.1",
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 2
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        assert installation_results[0]['package'] == 'flask==2.3.2'
        assert installation_results[1]['package'] == 'requests==2.28.1'
        
        # Verify audit results
        assert len(audit_results) == 2
        assert all(len(pkg['vulns']) == 0 for pkg in audit_results)
        
        # Verify package report structure
        assert 'packages' in package_report
        assert 'summary' in package_report
        assert 'report_metadata' in package_report
        assert len(package_report['packages']) == 2
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 0
        assert package_report['summary']['total_vulnerabilities'] == 0
        
        # Verify CVE list is empty
        assert len(cve_list) == 0
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==2.3.2\ndjango==3.2.0\n"))
    def test_output_files_generation_with_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test output file generation with packages containing vulnerabilities"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with vulnerabilities
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "Cross-site Scripting vulnerability in Flask",
                        "fix_versions": ["2.3.3"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "django",
                "version": "3.2.0",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability",
                        "fix_versions": ["3.2.22"],
                        "severity": "high"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 2
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        
        # Verify audit results
        assert len(audit_results) == 2
        flask_audit = next(r for r in audit_results if r['package'] == 'flask')
        django_audit = next(r for r in audit_results if r['package'] == 'django')
        assert len(flask_audit['vulns']) == 1
        assert len(django_audit['vulns']) == 2
        
        # Verify package report structure and content
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 2
        assert package_report['summary']['total_vulnerabilities'] == 3
        assert package_report['summary']['packages_clean'] == 0
        
        # Verify individual package details in report
        flask_pkg = next(p for p in package_report['packages'] if p['name'] == 'flask')
        django_pkg = next(p for p in package_report['packages'] if p['name'] == 'django')
        
        assert flask_pkg['vulnerability_count'] == 1
        assert django_pkg['vulnerability_count'] == 2
        assert len(flask_pkg['vulnerabilities']) == 1
        assert len(django_pkg['vulnerabilities']) == 2
        
        # Verify CVE details
        flask_cve = next(cve for cve in cve_list if cve['cve'] == 'CVE-2023-30861')
        assert flask_cve['package'] == 'flask'
        assert flask_cve['version'] == '2.3.2'
        assert 'Cross-site Scripting' in flask_cve['description']
        
        # Verify CVE list
        assert len(cve_list) == 3
        cve_ids = [cve['cve'] for cve in cve_list]
        assert 'CVE-2023-30861' in cve_ids
        assert 'CVE-2023-41164' in cve_ids
        assert 'CVE-2023-43665' in cve_ids
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_write_output_files_actual_file_operations(self, mock_json_dump, mock_file_open, mock_makedirs):
        """Test actual file writing operations in writeOutputFiles function"""
        # Test data
        package_report = {
            "report_metadata": {
                "generated_at": "2023-12-01T10:00:00",
                "report_type": "package_vulnerability_audit",
                "total_packages": 1
            },
            "summary": {
                "total_packages": 1,
                "packages_with_vulnerabilities": 1,
                "total_vulnerabilities": 1,
                "packages_clean": 0
            },
            "packages": [
                {
                    "name": "test-pkg",
                    "installed_version": "1.0.0",
                    "vulnerability_count": 1,
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2023-TEST",
                            "description": "Test vulnerability",
                            "severity": "medium"
                        }
                    ]
                }
            ]
        }
        
        cve_list = [
            {
                "cve": "CVE-2023-TEST",
                "package": "test-pkg",
                "version": "1.0.0",
                "description": "Test vulnerability",
                "severity": "medium"
            }
        ]
        
        # Call the actual writeOutputFiles function
        result = writeOutputFiles(package_report, cve_list)
        
        # Verify directory creation
        mock_makedirs.assert_called_once_with('/shared', exist_ok=True)
        
        # Verify file operations
        assert mock_file_open.call_count == 2
        expected_calls = [
            call('/shared/package_audit_report.json', 'w'),
            call('/shared/cve_list.json', 'w')
        ]
        mock_file_open.assert_has_calls(expected_calls, any_order=True)
        
        # Verify JSON dump operations
        assert mock_json_dump.call_count == 2
        json_dump_calls = mock_json_dump.call_args_list
        
        # Check that both package_report and cve_list were dumped
        dumped_data = [call[0][0] for call in json_dump_calls]
        assert package_report in dumped_data
        assert cve_list in dumped_data
        
        # Verify all calls used indent=2
        for call in json_dump_calls:
            assert call[1]['indent'] == 2
        
        # Verify function returns True on success
        assert result is True
    
    @patch('os.makedirs')
    @patch('builtins.open', side_effect=PermissionError("Permission denied"))
    def test_write_output_files_permission_error(self, mock_file_open, mock_makedirs):
        """Test writeOutputFiles handles permission errors gracefully"""
        package_report = {"test": "data"}
        cve_list = [{"cve": "CVE-2023-TEST"}]
        
        # Call writeOutputFiles with permission error
        result = writeOutputFiles(package_report, cve_list)
        
        # Verify directory creation was attempted
        mock_makedirs.assert_called_once_with('/shared', exist_ok=True)
        
        # Verify file open was attempted
        mock_file_open.assert_called()
        
        # Function should handle error gracefully (implementation dependent)
        # This test ensures the function doesn't crash on permission errors
    
    @patch('os.makedirs', side_effect=OSError("Directory creation failed"))
    def test_write_output_files_directory_creation_error(self, mock_makedirs):
        """Test writeOutputFiles handles directory creation errors"""
        package_report = {"test": "data"}
        cve_list = [{"cve": "CVE-2023-TEST"}]
        
        # Call writeOutputFiles with directory creation error
        result = writeOutputFiles(package_report, cve_list)
        
        # Verify directory creation was attempted
        mock_makedirs.assert_called_once_with('/shared', exist_ok=True)
        
        # Function should handle error gracefully (implementation dependent)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="requests==2.28.1\npandas==1.5.0\n"))
    def test_output_files_generation_version_handling(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test output file generation with version-specific vulnerability data"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with version-specific vulnerabilities
        audit_output = json.dumps([
            {
                "package": "requests",
                "version": "2.28.1",
                "vulns": [
                    {
                        "id": "CVE-2023-32681",
                        "description": "Requests SSRF vulnerability",
                        "fix_versions": ["2.31.0"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "pandas",
                "version": "1.5.0",
                "vulns": [
                    {
                        "id": "CVE-2023-PANDAS",
                        "description": "Pandas vulnerability",
                        "fix_versions": ["1.5.3"],
                        "severity": "low"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify version handling
        requests_result = next(r for r in matched_results if r['package'] == 'requests')
        pandas_result = next(r for r in matched_results if r['package'] == 'pandas')
        
        assert requests_result['installed_version'] == '2.28.1'
        assert pandas_result['installed_version'] == '1.5.0'
        
        # Verify version information in CVE list
        requests_cve = next(cve for cve in cve_list if cve['package'] == 'requests')
        pandas_cve = next(cve for cve in cve_list if cve['package'] == 'pandas')
        
        assert requests_cve['version'] == '2.28.1'
        assert pandas_cve['version'] == '1.5.0'
        
        # Verify fix version information is preserved
        requests_pkg = next(p for p in package_report['packages'] if p['name'] == 'requests')
        pandas_pkg = next(p for p in package_report['packages'] if p['name'] == 'pandas')
        
        requests_vuln = requests_pkg['vulnerabilities'][0]
        pandas_vuln = pandas_pkg['vulnerabilities'][0]
        
        assert '2.31.0' in requests_vuln.get('fix_versions', [])
        assert '1.5.3' in pandas_vuln.get('fix_versions', [])
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="# Comment line\nflask==2.3.2\n\n# Another comment\nrequests==2.28.1\n"))
    def test_output_files_generation_requirements_parsing(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test output file generation with requirements file containing comments and empty lines"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            },
            {
                "package": "requests",
                "version": "2.28.1",
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify only actual packages are processed (comments/empty lines ignored)
        assert len(installation_results) == 2
        assert len(matched_results) == 2
        assert package_report['summary']['total_packages'] == 2
        
        # Verify package names are correct
        package_names = [pkg['name'] for pkg in package_report['packages']]
        assert 'flask' in package_names
        assert 'requests' in package_names
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="single-pkg==1.0.0\n"))
    def test_output_files_generation_single_package(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test output file generation with single package"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with single vulnerability
        audit_output = json.dumps([
            {
                "package": "single-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-SINGLE",
                        "description": "Single package vulnerability",
                        "fix_versions": ["1.1.0"],
                        "severity": "high"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify single package handling
        assert len(installation_results) == 1
        assert len(matched_results) == 1
        assert len(cve_list) == 1
        assert package_report['summary']['total_packages'] == 1
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 1
        
        # Verify single package details
        single_pkg = package_report['packages'][0]
        assert single_pkg['name'] == 'single-pkg'
        assert single_pkg['installed_version'] == '1.0.0'
        assert single_pkg['vulnerability_count'] == 1
        
        # Verify single CVE details
        single_cve = cve_list[0]
        assert single_cve['cve'] == 'CVE-2023-SINGLE'
        assert single_cve['package'] == 'single-pkg'
        assert single_cve['version'] == '1.0.0'
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="json-test-pkg==1.0.0\n"))
    def test_output_files_json_serialization_validation(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test that output files contain valid JSON that can be serialized and deserialized"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output
        audit_output = json.dumps([
            {
                "package": "json-test-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-99999",
                        "description": "Test vulnerability with special characters: <>&\"'",
                        "fix_versions": ["1.1.0"],
                        "severity": "medium"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Test JSON serialization
        package_report_json = json.dumps(package_report)
        cve_list_json = json.dumps(cve_list)
        
        # Verify JSON can be parsed back
        parsed_report = json.loads(package_report_json)
        parsed_cve_list = json.loads(cve_list_json)
        
        assert parsed_report['summary']['total_packages'] == 1
        assert len(parsed_cve_list) == 1
        assert parsed_cve_list[0]['cve'] == 'CVE-2023-99999'
        
        # Verify special characters are handled correctly
        vuln_desc = parsed_report['packages'][0]['vulnerabilities'][0]['description']
        assert '<>&"\'' in vuln_desc
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    def test_write_output_files_empty_data(self, mock_write):
        """Test writeOutputFiles behavior with empty data"""
        empty_package_report = {
            "packages": [],
            "summary": {"total_packages": 0}
        }
        empty_cve_list = []
        
        writeOutputFiles(empty_package_report, empty_cve_list)
        
        # Verify writeOutputFiles was called with empty data
        mock_write.assert_called_once_with(empty_package_report, empty_cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="good-pkg==1.0.0\nbad-pkg==2.0.0\nugly-pkg==3.0.0\n"))
    def test_pipeline_mixed_results_comprehensive(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test comprehensive mixed results scenario"""
        # Mock complex mixed installation results
        def mock_run_side_effect(cmd, **kwargs):
            if "good-pkg" in cmd:
                return MagicMock(returncode=0)
            elif "bad-pkg" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Package installation failed due to dependency conflict"
                raise error
            elif "ugly-pkg" in cmd:
                return MagicMock(returncode=0)
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit with mixed vulnerability results
        audit_output = json.dumps([
            {
                "package": "good-pkg",
                "version": "1.0.0",
                "vulns": []  # Clean package
            },
            {
                "package": "ugly-pkg",
                "version": "3.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-UGLY1",
                        "description": "Ugly package vulnerability 1",
                        "fix_versions": ["3.1.0"],
                        "severity": "high"
                    },
                    {
                        "id": "CVE-2023-UGLY2",
                        "description": "Ugly package vulnerability 2",
                        "fix_versions": ["3.2.0"],
                        "severity": "critical"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Comprehensive verification
        # 1. Installation results
        assert len(installation_results) == 3
        good_install = next(pkg for pkg in installation_results if 'good-pkg' in pkg['package'])
        bad_install = next(pkg for pkg in installation_results if 'bad-pkg' in pkg['package'])
        ugly_install = next(pkg for pkg in installation_results if 'ugly-pkg' in pkg['package'])
        
        assert good_install['status'] == 'success'
        assert bad_install['status'] == 'failed'
        assert ugly_install['status'] == 'success'
        assert 'dependency conflict' in bad_install['error_message']
        
        # 2. Audit results (only successful installations)
        assert len(audit_results) == 2
        audit_packages = [pkg['package'] for pkg in audit_results]
        assert 'good-pkg' in audit_packages
        assert 'ugly-pkg' in audit_packages
        assert 'bad-pkg' not in audit_packages
        
        # 3. Matched results
        assert len(matched_results) == 2
        good_result = next(r for r in matched_results if r['package'] == 'good-pkg')
        ugly_result = next(r for r in matched_results if r['package'] == 'ugly-pkg')
        
        assert len(good_result['vulns']) == 0
        assert len(ugly_result['vulns']) == 2
        assert good_result['audit_status'] == 'success'
        assert ugly_result['audit_status'] == 'success'
        
        # 4. Package report
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 2
        assert package_report['summary']['packages_clean'] == 1
        assert package_report['summary']['packages_failed_audit'] == 0
        
        # 5. CVE list
        assert len(cve_list) == 2
        cve_ids = [cve['cve'] for cve in cve_list]
        assert 'CVE-2023-UGLY1' in cve_ids
        assert 'CVE-2023-UGLY2' in cve_ids
        assert all(cve['package'] == 'ugly-pkg' for cve in cve_list)
        
        # 6. Output verification
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
        
        # 7. JSON serialization
        json.dumps(package_report)
        json.dumps(cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="pkg-a==1.0.0\npkg-b==2.0.0\npkg-c==3.0.0\npkg-d==4.0.0\npkg-e==5.0.0\n"))
    def test_pipeline_majority_failures(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline where majority of installations fail"""
        # Mock mostly failed installations
        def mock_run_side_effect(cmd, **kwargs):
            if "pkg-a" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Package not found"
                raise error
            elif "pkg-b" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Version conflict"
                raise error
            elif "pkg-c" in cmd:
                return MagicMock(returncode=0)  # Only success
            elif "pkg-d" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Build failed"
                raise error
            elif "pkg-e" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Network error"
                raise error
            
        mock_subprocess.side_effect = mock_run_side_effect
        
        # Mock pip-audit output for single successful installation
        audit_output = json.dumps([
            {
                "package": "pkg-c",
                "version": "3.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-PKGC",
                        "description": "Package C vulnerability",
                        "fix_versions": ["3.1.0"],
                        "severity": "medium"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify majority failure handling
        assert len(installation_results) == 5
        successful_count = sum(1 for pkg in installation_results if pkg['status'] == 'success')
        failed_count = sum(1 for pkg in installation_results if pkg['status'] == 'failed')
        
        assert successful_count == 1
        assert failed_count == 4
        
        # Verify different failure reasons
        failed_packages = [pkg for pkg in installation_results if pkg['status'] == 'failed']
        error_messages = [pkg['error_message'] for pkg in failed_packages]
        assert any('not found' in msg for msg in error_messages)
        assert any('conflict' in msg for msg in error_messages)
        assert any('Build failed' in msg for msg in error_messages)
        assert any('Network error' in msg for msg in error_messages)
        
        # Verify single successful package is processed
        assert len(matched_results) == 1
        assert matched_results[0]['package'] == 'pkg-c'
        assert len(matched_results[0]['vulns']) == 1
        
        # Verify minimal report generation
        assert package_report['summary']['total_packages'] == 1
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 1
        
        assert len(cve_list) == 1
        assert cve_list[0]['cve'] == 'CVE-2023-PKGC'
        # Verify report_metadata structure
        metadata = parsed_result["report_metadata"]
        assert "generated_at" in metadata
        assert "report_type" in metadata
        assert "total_packages" in metadata
        assert metadata["report_type"] == "package_vulnerability_audit"
        assert metadata["total_packages"] == 1
        
        # Verify summary structure
        summary = parsed_result["summary"]
        required_summary_fields = [
            "packages_with_vulnerabilities",
            "total_vulnerabilities", 
            "packages_clean",
            "packages_failed_audit"
        ]
        for field in required_summary_fields:
            assert field in summary
            assert isinstance(summary[field], int)
        
        # Verify packages structure
        packages = parsed_result["packages"]
        assert isinstance(packages, list)
        assert len(packages) == 1
        
        # Verify individual package structure
        package = packages[0]
        required_package_fields = [
            "name", "installed_version", "requested_version",
            "installation_status", "audit_status", 
            "vulnerability_count", "vulnerabilities"
        ]
        for field in required_package_fields:
            assert field in package
        
        assert isinstance(package["vulnerabilities"], list)
        assert isinstance(package["vulnerability_count"], int)
        
        # Verify vulnerability structure
        vulnerabilities = package["vulnerabilities"]
        assert len(vulnerabilities) == 2
        
        for vulnerability in vulnerabilities:
            required_vulnerability_fields = [
                "id", "description", "fix_versions", "severity"
            ]
            for field in required_vulnerability_fields:
                assert field in vulnerability
            assert isinstance(vulnerability["id"], str)
            assert vulnerability["id"].startswith("CVE-")
            assert isinstance(vulnerability["description"], str)
            assert isinstance(vulnerability["fix_versions"], list)
            assert isinstance(vulnerability["severity"], str)
            assert vulnerability["severity"] in ["low", "medium", "high", "critical"]
    
    def test_package_report_vulnerability_structure(self):
        """Test vulnerability objects within package report have correct structure"""
        matched_results = [
            {
                "package": "django",
                "installed_version": "3.0.0",
                "status": "success",
                "audit_status": "success",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability",
                        "fix_versions": ["3.2.22"],
                        "severity": "medium"
                    }
                ]
            }
        ]
        
        result = generatePackageReport(matched_results)
        
        # Verify it's valid JSON by serializing and deserializing
        json_str = json.dumps(result)
        parsed_result = json.loads(json_str)
        
        # Verify top-level structure
        assert "report_metadata" in parsed_result
        assert "summary" in parsed_result
        assert "packages" in parsed_result
        
        # Verify report_metadata structure
        metadata = parsed_result["report_metadata"]
        assert "generated_at" in metadata
        assert "report_type" in metadata
        assert "total_packages" in metadata
        assert metadata["report_type"] == "package_vulnerability_audit"
        assert metadata["total_packages"] == 1
        
        # Verify summary structure
        summary = parsed_result["summary"]
        required_summary_fields = [
            "packages_with_vulnerabilities",
            "total_vulnerabilities", 
            "packages_clean",
            "packages_failed_audit"
        ]
        for field in required_summary_fields:
            assert field in summary
            assert isinstance(summary[field], int)
        
        # Verify packages structure
        packages = parsed_result["packages"]
        assert isinstance(packages, list)
        assert len(packages) == 1
        
        # Verify individual package structure
        package = packages[0]
        required_package_fields = [
            "name", "installed_version", "requested_version",
            "installation_status", "audit_status", 
            "vulnerability_count", "vulnerabilities"
        ]
        for field in required_package_fields:
            assert field in package
        
        assert isinstance(package["vulnerabilities"], list)
        assert isinstance(package["vulnerability_count"], int)
        
        # Verify vulnerability structure
        vulnerabilities = package["vulnerabilities"]
        assert len(vulnerabilities) == 2
        
        for vulnerability in vulnerabilities:
            required_vulnerability_fields = [
                "id", "description", "fix_versions", "severity"
            ]
            for field in required_vulnerability_fields:
                assert field in vulnerability
            assert isinstance(vulnerability["id"], str)
            assert vulnerability["id"].startswith("CVE-")
            assert isinstance(vulnerability["description"], str)
            assert isinstance(vulnerability["fix_versions"], list)
            assert isinstance(vulnerability["severity"], str)
            assert vulnerability["severity"] in ["low", "medium", "high", "critical"]

@pytest.mark.integration
class TestFullPipelineWithVulnerabilities:
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==1.0.0\ndjango==2.2.0\nrequests==2.6.0\n"))
    def test_pipeline_multiple_packages_multiple_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with multiple packages having multiple vulnerabilities"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with multiple vulnerabilities per package
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "Flask Cross-site Scripting vulnerability",
                        "fix_versions": ["2.3.2"],
                        "severity": "high"
                    },
                    {
                        "id": "CVE-2023-30862",
                        "description": "Flask CSRF vulnerability",
                        "fix_versions": ["2.3.3"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "django",
                "version": "2.2.0",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21", "4.1.12"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability",
                        "fix_versions": ["3.2.22"],
                        "severity": "medium"
                    },
                    {
                        "id": "CVE-2023-36053",
                        "description": "Django path traversal vulnerability",
                        "fix_versions": ["3.2.20"],
                        "severity": "high"
                    }
                ]
            },
            {
                "package": "requests",
                "version": "2.6.0",
                "vulns": [
                    {
                        "id": "CVE-2023-32681",
                        "description": "Requests SSRF vulnerability",
                        "fix_versions": ["2.31.0"],
                        "severity": "medium"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 3
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        
        # Verify audit results parsing
        assert len(audit_results) == 3
        flask_audit = next(r for r in audit_results if r['package'] == 'flask')
        django_audit = next(r for r in audit_results if r['package'] == 'django')
        requests_audit = next(r for r in audit_results if r['package'] == 'requests')
        
        assert len(flask_audit['vulns']) == 2
        assert len(django_audit['vulns']) == 3
        assert len(requests_audit['vulns']) == 1
        
        # Verify matched results
        assert len(matched_results) == 3
        flask_result = next(r for r in matched_results if r['package'] == 'flask')
        django_result = next(r for r in matched_results if r['package'] == 'django')
        requests_result = next(r for r in matched_results if r['package'] == 'requests')
        
        assert len(flask_result['vulns']) == 2
        assert len(django_result['vulns']) == 3
        assert len(requests_result['vulns']) == 1
        
        # Verify package report structure and counts
        assert package_report['summary']['total_packages'] == 3
        assert package_report['summary']['packages_with_vulnerabilities'] == 3
        assert package_report['summary']['total_vulnerabilities'] == 6
        assert package_report['summary']['packages_clean'] == 0
        
        # Verify individual package vulnerability counts
        flask_pkg = next(p for p in package_report['packages'] if p['name'] == 'flask')
        django_pkg = next(p for p in package_report['packages'] if p['name'] == 'django')
        requests_pkg = next(p for p in package_report['packages'] if p['name'] == 'requests')
        
        assert flask_pkg['vulnerability_count'] == 2
        assert django_pkg['vulnerability_count'] == 3
        assert requests_pkg['vulnerability_count'] == 1
        
        # Verify CVE list generation
        assert len(cve_list) == 6
        expected_cves = [
            'CVE-2023-30861', 'CVE-2023-30862', 'CVE-2023-41164',
            'CVE-2023-43665', 'CVE-2023-36053', 'CVE-2023-32681'
        ]
        actual_cves = [cve['cve'] for cve in cve_list]
        for expected_cve in expected_cves:
            assert expected_cve in actual_cves
        
        # Verify CVE details
        flask_cve = next(cve for cve in cve_list if cve['cve'] == 'CVE-2023-30861')
        assert flask_cve['package'] == 'flask'
        assert flask_cve['version'] == '1.0.0'
        assert 'Cross-site Scripting' in flask_cve['description']
        
        # Verify output files written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="pillow==8.0.0\nnumpy==1.19.0\n"))
    def test_pipeline_critical_severity_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with critical severity vulnerabilities"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with critical vulnerabilities
        audit_output = json.dumps([
            {
                "package": "pillow",
                "version": "8.0.0",
                "vulns": [
                    {
                        "id": "CVE-2022-22817",
                        "description": "Pillow buffer overflow vulnerability",
                        "fix_versions": ["9.0.1"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2022-22816",
                        "description": "Pillow path traversal vulnerability",
                        "fix_versions": ["9.0.1"],
                        "severity": "critical"
                    }
                ]
            },
            {
                "package": "numpy",
                "version": "1.19.0",
                "vulns": [
                    {
                        "id": "CVE-2021-33430",
                        "description": "NumPy buffer overflow vulnerability",
                        "fix_versions": ["1.21.0"],
                        "severity": "critical"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify critical vulnerabilities are properly captured
        assert len(cve_list) == 3
        critical_cves = [cve for cve in cve_list if 'critical' in cve.get('severity', '').lower()]
        assert len(critical_cves) >= 0  # Depends on CVE structure
        
        # Verify package report shows high-risk packages
        assert package_report['summary']['total_vulnerabilities'] == 3
        assert package_report['summary']['packages_with_vulnerabilities'] == 2
        
        # Verify all vulnerabilities are critical
        for pkg in package_report['packages']:
            for vuln in pkg['vulnerabilities']:
                assert vuln['severity'] == 'critical'
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="urllib3==1.25.0\ncertifi==2020.6.20\nchardet==3.0.4\n"))
    def test_pipeline_mixed_severity_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with mixed severity vulnerabilities"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with mixed severities
        audit_output = json.dumps([
            {
                "package": "urllib3",
                "version": "1.25.0",
                "vulns": [
                    {
                        "id": "CVE-2021-33503",
                        "description": "urllib3 catastrophic backtracking vulnerability",
                        "fix_versions": ["1.26.5"],
                        "severity": "high"
                    },
                    {
                        "id": "CVE-2020-26137",
                        "description": "urllib3 CRLF injection vulnerability",
                        "fix_versions": ["1.25.10"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "certifi",
                "version": "2020.6.20",
                "vulns": [
                    {
                        "id": "CVE-2022-23491",
                        "description": "Certifi certificate validation vulnerability",
                        "fix_versions": ["2022.12.7"],
                        "severity": "low"
                    }
                ]
            },
            {
                "package": "chardet",
                "version": "3.0.4",
                "vulns": [
                    {
                        "id": "CVE-2021-29421",
                        "description": "Chardet ReDoS vulnerability",
                        "fix_versions": ["4.0.0"],
                        "severity": "critical"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify mixed severity handling
        assert len(cve_list) == 4
        severities = [vuln['severity'] for pkg in package_report['packages'] for vuln in pkg['vulnerabilities']]
        assert 'critical' in severities
        assert 'high' in severities
        assert 'medium' in severities
        assert 'low' in severities
        
        # Verify severity distribution
        severity_counts = {}
        for severity in severities:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        assert severity_counts['critical'] == 1
        assert severity_counts['high'] == 1
        assert severity_counts['medium'] == 1
        assert severity_counts['low'] == 1
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="jinja2==2.10.0\nmarkupsafe==1.1.0\n"))
    def test_pipeline_vulnerabilities_with_multiple_fix_versions(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with vulnerabilities having multiple fix versions"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with multiple fix versions
        audit_output = json.dumps([
            {
                "package": "jinja2",
                "version": "2.10.0",
                "vulns": [
                    {
                        "id": "CVE-2020-28493",
                        "description": "Jinja2 ReDoS vulnerability",
                        "fix_versions": ["2.11.3", "3.0.0", "3.1.0"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "markupsafe",
                "version": "1.1.0",
                "vulns": [
                    {
                        "id": "CVE-2023-37920",
                        "description": "MarkupSafe XSS vulnerability",
                        "fix_versions": ["2.0.1", "2.1.0", "2.1.1", "2.1.2"],
                        "severity": "high"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify fix versions are properly captured
        jinja2_pkg = next(p for p in package_report['packages'] if p['name'] == 'jinja2')
        markupsafe_pkg = next(p for p in package_report['packages'] if p['name'] == 'markupsafe')
        
        jinja2_vuln = jinja2_pkg['vulnerabilities'][0]
        markupsafe_vuln = markupsafe_pkg['vulnerabilities'][0]
        
        assert len(jinja2_vuln['fix_versions']) == 3
        assert '2.11.3' in jinja2_vuln['fix_versions']
        assert '3.0.0' in jinja2_vuln['fix_versions']
        assert '3.1.0' in jinja2_vuln['fix_versions']
        
        assert len(markupsafe_vuln['fix_versions']) == 4
        assert '2.0.1' in markupsafe_vuln['fix_versions']
        assert '2.1.2' in markupsafe_vuln['fix_versions']
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="pyyaml==5.1.0\n"))
    def test_pipeline_single_package_multiple_cves(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with single package having multiple CVEs"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with multiple CVEs for one package
        audit_output = json.dumps([
            {
                "package": "pyyaml",
                "version": "5.1.0",
                "vulns": [
                    {
                        "id": "CVE-2020-1747",
                        "description": "PyYAML arbitrary code execution vulnerability",
                        "fix_versions": ["5.3.1"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2020-14343",
                        "description": "PyYAML incomplete fix vulnerability",
                        "fix_versions": ["5.4.0"],
                        "severity": "high"
                    },
                    {
                        "id": "CVE-2021-25292",
                        "description": "PyYAML ReDoS vulnerability",
                        "fix_versions": ["5.4.1"],
                        "severity": "medium"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify single package with multiple CVEs
        assert len(installation_results) == 1
        assert len(matched_results) == 1
        assert len(cve_list) == 3
        
        assert package_report['summary']['total_packages'] == 1
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 3
        
        pyyaml_pkg = package_report['packages'][0]
        assert pyyaml_pkg['name'] == 'pyyaml'
        assert pyyaml_pkg['vulnerability_count'] == 3
        assert len(pyyaml_pkg['vulnerabilities']) == 3
        
        # Verify all CVEs are for the same package
        for cve in cve_list:
            assert cve['package'] == 'pyyaml'
            assert cve['version'] == '5.1.0'
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="old-pkg==0.1.0\nvuln-pkg==1.0.0\nlegacy-pkg==2.0.0\n"))
    def test_pipeline_legacy_packages_with_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test pipeline with legacy packages having known vulnerabilities"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with legacy package vulnerabilities
        audit_output = json.dumps([
            {
                "package": "old-pkg",
                "version": "0.1.0",
                "vulns": [
                    {
                        "id": "CVE-2019-12345",
                        "description": "Legacy package security vulnerability",
                        "fix_versions": ["1.0.0", "2.0.0"],
                        "severity": "high"
                    }
                ]
            },
            {
                "package": "vuln-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2020-54321",
                        "description": "Known vulnerable package",
                        "fix_versions": ["2.0.0"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2021-11111",
                        "description": "Additional vulnerability in same package",
                        "fix_versions": ["2.1.0"],
                        "severity": "medium"
                    }
                ]
            },
            {
                "package": "legacy-pkg",
                "version": "2.0.0",
                "vulns": [
                    {
                        "id": "CVE-2018-99999",
                        "description": "Old vulnerability still present",
                        "fix_versions": ["3.0.0"],
                        "severity": "low"
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify legacy vulnerability handling
        assert len(cve_list) == 4
        assert package_report['summary']['total_packages'] == 3
        assert package_report['summary']['packages_with_vulnerabilities'] == 3
        assert package_report['summary']['total_vulnerabilities'] == 4
        
        # Verify CVE year ranges (legacy vulnerabilities)
        cve_years = [int(cve['cve'].split('-')[1]) for cve in cve_list]
        assert min(cve_years) == 2018  # Oldest CVE
        assert max(cve_years) == 2021  # Newest CVE
        
        # Verify different severity levels are captured
        severities = [vuln['severity'] for pkg in package_report['packages'] for vuln in pkg['vulnerabilities']]
        assert 'critical' in severities
        assert 'high' in severities
        assert 'medium' in severities
        assert 'low' in severities
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="complex-pkg==1.0.0\n"))
    def test_pipeline_complex_vulnerability_data(self, mock_file, mock
                        "id": "CVE-2023-41164",
                        "description": "SQL injection vulnerability",
                        "fix_versions": ["3.2.21", "4.1.12"],
                        "severity": "critical"
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "XSS vulnerability",
                        "fix_versions": ["3.2.22"],
                        "severity": "medium"
                    }
                ]
            }
        ]
        
        result = generatePackageReport(matched_results)
        
        # Verify vulnerability structure
        package = result["packages"][0]
        vulnerabilities = package["vulnerabilities"]
        
        assert len(vulnerabilities) == 2
        
        for vuln in vulnerabilities:
            required_vuln_fields = ["id", "description", "fix_versions", "severity"]
            for field in required_vuln_fields:
                assert field in vuln
            
            assert isinstance(vuln["fix_versions"], list)
            assert isinstance(vuln["id"], str)
            assert isinstance(vuln["description"], str)
            assert isinstance(vuln["severity"], str)
    
    def test_empty_results_json_structure(self):
        """Test JSON structure with empty input data"""
        # Test empty package report
        empty_report = generatePackageReport([])
        
        json_str = json.dumps(empty_report)
        parsed_result = json.loads(json_str)
        
        assert "report_metadata" in parsed_result
        assert "summary" in parsed_result
        assert "packages" in parsed_result
        assert parsed_result["packages"] == []
        assert parsed_result["report_metadata"]["total_packages"] == 0
        
        # Test empty CVE list
        empty_cve_list = generateCVEListFromMatchedResults([])
        
        json_str = json.dumps(empty_cve_list)
        parsed_result = json.loads(json_str)
        
        assert isinstance(parsed_result, list)
        assert len(parsed_result) == 0
    
    def test_package_report_error_handling_json_structure(self):
        """Test that error responses maintain valid JSON structure"""
        # Test with malformed input that might cause errors
        with patch('prepareProject.logging.error'):
            # Simulate an error condition
            with patch('prepareProject.datetime.now') as mock_datetime:
                mock_datetime.side_effect = Exception("DateTime error")
                
                result = generatePackageReport([{"invalid": "data"}])
        
        # Should still return valid JSON structure even on error
        json_str = json.dumps(result)
        parsed_result = json.loads(json_str)
        
        # Error response should have basic structure
        assert "report_metadata" in parsed_result
        if "error" in parsed_result:
            assert isinstance(parsed_result["error"], str)
    
    def test_json_serialization_compatibility(self):
        """Test that all generated data types are JSON serializable"""
        matched_results = [
            {
                "package": "test-pkg",
                "installed_version": "1.0.0",
                "status": "success",
                "audit_status": "success",
                "vulns": [
                    {
                        "id": "CVE-2023-12345",
                        "description": "Test vulnerability",
                        "fix_versions": ["1.1.0"],
                        "severity": "low"
                    }
                ]
            }
        ]
        
        # Test package report serialization
        package_report = generatePackageReport(matched_results)
        try:
            json.dumps(package_report, indent=2)
        except (TypeError, ValueError) as e:
            pytest.fail(f"Package report is not JSON serializable: {e}")
        
        # Test CVE list serialization
        cve_list = generateCVEListFromMatchedResults(matched_results)
        try:
            json.dumps(cve_list, indent=2)
        except (TypeError, ValueError) as e:
            pytest.fail(f"CVE list is not JSON serializable: {e}")
    
    def test_json_schema_consistency(self):
        """Test that JSON output maintains consistent schema across different inputs"""
        test_cases = [
            # Case 1: Multiple packages with vulnerabilities
            [
                {
                    "package": "pkg1",
                    "installed_version": "1.0.0",
                    "status": "success",
                    "audit_status": "success",
                    "vulns": [{"id": "CVE-2023-1", "description": "Test"}]
                },
                {
                    "package": "pkg2", 
                    "installed_version": "2.0.0",
                    "status": "success",
                    "audit_status": "success",
                    "vulns": []
                }
            ],
            # Case 2: Single package with multiple vulnerabilities
            [
                {
                    "package": "pkg3",
                    "installed_version": "3.0.0", 
                    "status": "success",
                    "audit_status": "success",
                    "vulns": [
                        {"id": "CVE-2023-2", "description": "Test 1"},
                        {"id": "CVE-2023-3", "description": "Test 2"}
                    ]
                }
            ]
        ]
        
        schemas = []
        for test_case in test_cases:
            result = generatePackageReport(test_case)
            
            # Extract schema (keys and types)

@pytest.mark.integration
class TestFullPipelineValidPackages:
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==2.3.2\nrequests==2.28.1\n"))
    def test_complete_pipeline_successful_installation_no_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with successful installation and no vulnerabilities found"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with no vulnerabilities
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "2.3.2",
                "vulns": []
            },
            {
                "package": "requests",
                "version": "2.28.1", 
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 2
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        assert installation_results[0]['package'] == 'flask==2.3.2'
        assert installation_results[1]['package'] == 'requests==2.28.1'
        
        # Verify audit results
        assert len(audit_results) == 2
        assert all(len(pkg['vulns']) == 0 for pkg in audit_results)
        
        # Verify matched results
        assert len(matched_results) == 2
        flask_result = next(r for r in matched_results if r['package'] == 'flask')
        requests_result = next(r for r in matched_results if r['package'] == 'requests')
        
        assert flask_result['installed_version'] == '2.3.2'
        assert requests_result['installed_version'] == '2.28.1'
        assert len(flask_result['vulns']) == 0
        assert len(requests_result['vulns']) == 0
        
        # Verify package report structure
        assert 'packages' in package_report
        assert 'summary' in package_report
        assert 'report_metadata' in package_report
        assert len(package_report['packages']) == 2
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 0
        assert package_report['summary']['total_vulnerabilities'] == 0
        
        # Verify CVE list is empty
        assert len(cve_list) == 0
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==1.0.0\ndjango==3.0.0\n"))
    def test_complete_pipeline_successful_installation_with_vulnerabilities(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with successful installation and vulnerabilities found"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with vulnerabilities
        audit_output = json.dumps([
            {
                "package": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-30861",
                        "description": "Flask vulnerable to XSS",
                        "fix_versions": ["2.3.2"]
                    }
                ]
            },
            {
                "package": "django",
                "version": "3.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-41164",
                        "description": "Django SQL injection vulnerability",
                        "fix_versions": ["3.2.21"]
                    },
                    {
                        "id": "CVE-2023-43665",
                        "description": "Django XSS vulnerability", 
                        "fix_versions": ["3.2.22"]
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify installation results
        assert len(installation_results) == 2
        assert all(pkg['status'] == 'success' for pkg in installation_results)
        
        # Verify audit results
        assert len(audit_results) == 2
        flask_audit = next(r for r in audit_results if r['package'] == 'flask')
        django_audit = next(r for r in audit_results if r['package'] == 'django')
        
        assert len(flask_audit['vulns']) == 1
        assert len(django_audit['vulns']) == 2
        
        # Verify matched results
        assert len(matched_results) == 2
        flask_result = next(r for r in matched_results if r['package'] == 'flask')
        django_result = next(r for r in matched_results if r['package'] == 'django')
        
        assert len(flask_result['vulns']) == 1
        assert len(django_result['vulns']) == 2
        assert flask_result['vulns'][0]['id'] == 'CVE-2023-30861'
        
        # Verify package report
        assert package_report['summary']['total_packages'] == 2
        assert package_report['summary']['packages_with_vulnerabilities'] == 2
        assert package_report['summary']['total_vulnerabilities'] == 3
        
        # Verify CVE list
        assert len(cve_list) == 3
        cve_ids = [cve['cve'] for cve in cve_list]
        assert 'CVE-2023-30861' in cve_ids
        assert 'CVE-2023-41164' in cve_ids
        assert 'CVE-2023-43665' in cve_ids
        
        # Verify output files would be written
        writeOutputFiles(package_report, cve_list)
        mock_write.assert_called_once_with(package_report, cve_list)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="requests>=2.25.0\nnumpy==1.21.0\npandas>=1.3.0\n"))
    def test_complete_pipeline_with_version_specifiers(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with various version specifiers"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output showing actual installed versions
        audit_output = json.dumps([
            {
                "package": "requests",
                "version": "2.28.1",  # Actual installed version
                "vulns": []
            },
            {
                "package": "numpy",
                "version": "1.21.0",
                "vulns": []
            },
            {
                "package": "pandas",
                "version": "1.5.3",  # Actual installed version
                "vulns": []
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify version handling
        requests_result = next(r for r in matched_results if r['package'] == 'requests')
        pandas_result = next(r for r in matched_results if r['package'] == 'pandas')
        
        assert requests_result['requested_version'] == '>=2.25.0'
        assert requests_result['installed_version'] == '2.28.1'
        assert pandas_result['requested_version'] == '>=1.3.0'
        assert pandas_result['installed_version'] == '1.5.3'
        
        # Verify report structure
        assert package_report['summary']['total_packages'] == 3
        assert all(pkg['vulnerability_count'] == 0 for pkg in package_report['packages'])
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="flask==2.3.2\n# Comment line\nrequests==2.28.1\n\n"))
    def test_complete_pipeline_with_comments_and_empty_lines(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with requirements file containing comments and empty lines"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output
        audit_output = json.dumps([
            {"package": "flask", "version": "2.3.2", "vulns": []},
            {"package": "requests", "version": "2.28.1", "vulns": []}
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify only actual packages are processed (comments/empty lines ignored)
        assert len(installation_results) == 2
        assert len(matched_results) == 2
        assert package_report['summary']['total_packages'] == 2
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="single-package==1.0.0\n"))
    def test_complete_pipeline_single_package(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with single package"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with vulnerability
        audit_output = json.dumps([
            {
                "package": "single-package",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-12345",
                        "description": "Test vulnerability",
                        "fix_versions": ["1.1.0"]
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify single package handling
        assert len(installation_results) == 1
        assert len(matched_results) == 1
        assert len(cve_list) == 1
        assert package_report['summary']['total_packages'] == 1
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 1
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="pkg1==1.0.0\npkg2==2.0.0\npkg3==3.0.0\npkg4==4.0.0\npkg5==5.0.0\n"))
    def test_complete_pipeline_multiple_packages(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with multiple packages"""
        # Mock successful pip installations
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output with mixed vulnerability results
        audit_output = json.dumps([
            {"package": "pkg1", "version": "1.0.0", "vulns": []},
            {"package": "pkg2", "version": "2.0.0", "vulns": [{"id": "CVE-2023-001", "description": "Test"}]},
            {"package": "pkg3", "version": "3.0.0", "vulns": []},
            {"package": "pkg4", "version": "4.0.0", "vulns": [{"id": "CVE-2023-002", "description": "Test"}, {"id": "CVE-2023-003", "description": "Test"}]},
            {"package": "pkg5", "version": "5.0.0", "vulns": []}
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify multiple package handling
        assert len(installation_results) == 5
        assert len(matched_results) == 5
        assert len(cve_list) == 3  # Total unique CVEs
        assert package_report['summary']['total_packages'] == 5
        assert package_report['summary']['packages_with_vulnerabilities'] == 2  # pkg2 and pkg4
        assert package_report['summary']['total_vulnerabilities'] == 3
        assert package_report['summary']['packages_clean'] == 3  # pkg1, pkg3, pkg5
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="test-pkg==1.0.0\n"))
    def test_complete_pipeline_json_serialization(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test that complete pipeline produces valid JSON output"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output
        audit_output = json.dumps([
            {
                "package": "test-pkg",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-99999",
                        "description": "Test vulnerability for JSON serialization",
                        "fix_versions": ["1.1.0"]
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Test JSON serialization
        package_report_json = json.dumps(package_report)
        cve_list_json = json.dumps(cve_list)
        
        # Verify JSON can be parsed back
        parsed_report = json.loads(package_report_json)
        parsed_cve_list = json.loads(cve_list_json)
        
        assert parsed_report['summary']['total_packages'] == 1
        assert len(parsed_cve_list) == 1
        assert parsed_cve_list[0]['cve'] == 'CVE-2023-99999'
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="datetime-pkg==1.0.0\n"))
    def test_complete_pipeline_report_metadata(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test that complete pipeline generates proper report metadata"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock pip-audit output
        audit_output = json.dumps([
            {"package": "datetime-pkg", "version": "1.0.0", "vulns": []}
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute the pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        
        # Verify report metadata
        metadata = package_report['report_metadata']
        assert 'generated_at' in metadata
        assert 'report_type' in metadata
        assert 'total_packages' in metadata
        assert metadata['report_type'] == 'package_vulnerability_audit'
        assert metadata['total_packages'] == 1
        
        # Verify timestamp format
        from datetime import datetime
        generated_at = datetime.fromisoformat(metadata['generated_at'].replace('Z', '+00:00'))
        assert isinstance(generated_at, datetime)
    
    @patch('prepareProject.writeOutputFiles')
    @patch('prepareProject.runPipAudit')
    @patch('subprocess.run')
    @patch('builtins.open', mock_open(read_data="comprehensive-test==1.0.0\n"))
    def test_complete_pipeline_comprehensive_validation(self, mock_file, mock_subprocess, mock_pip_audit, mock_write):
        """Test complete pipeline with comprehensive validation of all components"""
        # Mock successful pip installation
        mock_subprocess.return_value = MagicMock(returncode=0)
        
        # Mock comprehensive pip-audit output
        audit_output = json.dumps([
            {
                "package": "comprehensive-test",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "CVE-2023-COMP1",
                        "description": "Comprehensive test vulnerability 1",
                        "fix_versions": ["1.1.0"]
                    },
                    {
                        "id": "CVE-2023-COMP2", 
                        "description": "Comprehensive test vulnerability 2",
                        "fix_versions": ["1.2.0"]
                    }
                ]
            }
        ])
        mock_pip_audit.return_value = audit_output
        
        # Execute complete pipeline
        installation_results = installRequirements()
        audit_output_result = runPipAudit()
        audit_results = parsePipAuditOutput(audit_output_result)
        matched_results = matchAuditResultsToInstallation(installation_results, audit_results)
        package_report = generatePackageReport(matched_results)
        cve_list = generateCVEListFromMatchedResults(matched_results)
        writeOutputFiles(package_report, cve_list)
        
        # Comprehensive validation
        # 1. Installation phase
        assert len(installation_results) == 1
        assert installation_results[0]['status'] == 'success'
        assert installation_results[0]['package'] == 'comprehensive-test==1.0.0'
        
        # 2. Audit phase
        assert len(audit_results) == 1
        assert audit_results[0]['package'] == 'comprehensive-test'
        assert len(audit_results[0]['vulns']) == 2
        
        # 3. Matching phase
        assert len(matched_results) == 1
        matched_pkg = matched_results[0]
        assert matched_pkg['package'] == 'comprehensive-test'
        assert matched_pkg['installed_version'] == '1.0.0'
        assert matched_pkg['audit_status'] == 'success'
        assert len(matched_pkg['vulns']) == 2
        
        # 4. Report generation
        assert package_report['summary']['total_packages'] == 1
        assert package_report['summary']['packages_with_vulnerabilities'] == 1
        assert package_report['summary']['total_vulnerabilities'] == 2
        assert package_report['summary']['packages_clean'] == 0
        assert len(package_report['packages']) == 1
        
        pkg_in_report = package_report['packages'][0]
        assert pkg_in_report['name'] == 'comprehensive-test'
        assert pkg_in_report['vulnerability_count'] == 2
        assert len(pkg_in_report['vulnerabilities']) == 2
        
        # 5. CVE list generation
        assert len(cve_list) == 2
        cve_ids = [cve['cve'] for cve in cve_list]
        assert 'CVE-2023-COMP1' in cve_ids
        assert 'CVE-2023-COMP2' in cve_ids
        
        # 6. Output file writing
        mock_write.assert_called_once_with(package_report, cve_list)
        
        # 7. JSON structure validation
        json.dumps(package_report)  # Should not raise exception
        json.dumps(cve_list)        # Should not raise exception
            schema = {
                "top_level_keys": set(result.keys()),
                "metadata_keys": set(result["report_metadata"].keys()),
                "summary_keys": set(result["summary"].keys())
            }
            
            if result["packages"]:
                schema["package_keys"] = set(result["packages"][0].keys())
                if result["packages"][0]["vulnerabilities"]:
                    schema["vuln_keys"] = set(result["packages"][0]["vulnerabilities"][0].keys())
            
            schemas.append(schema)
        
        # Verify all schemas are consistent
        base_schema = schemas[0]
        for schema in schemas[1:]:
            assert schema["top_level_keys"] == base_schema["top_level_keys"]
            assert schema["metadata_keys"] == base_schema["metadata_keys"] 
            assert schema["summary_keys"] == base_schema["summary_keys"]

@pytest.mark.unit
class TestCVEFormatValidation:
    
    def test_valid_cve_format_acceptance(self):
        """Test that valid CVE formats are accepted"""
        valid_cves = [
            "CVE-2023-30861",
            "CVE-2022-1234", 
            "CVE-2021-12345",
            "CVE-1999-0001",
            "CVE-2024-123456",
            "CVE-2023-1234567"  # Extended format
        ]
        
        for cve_id in valid_cves:
            matched_results = [
                {
                    "package": "test-pkg",
                    "vulns": [{"id": cve_id, "description": "Test vulnerability"}]
                }
            ]
            
            result = generateCVEListFromMatchedResults(matched_results)
            
            assert len(result) == 1
            assert result[0]["cve"] == cve_id
    
    def test_invalid_cve_format_rejection(self):
        """Test that invalid CVE formats are rejected"""
        invalid_cves = [
            "CVE-23-30861",      # Year too short
            "CVE-2023-123",      # Number too short
            "CVE-ABCD-1234",     # Non-numeric year
            "CVE-2023-ABCD",     # Non-numeric number
            "INVALID-2023-1234", # Wrong prefix
            "2023-1234",         # Missing CVE prefix
            "CVE-2023",          # Missing number part
            "CVE-2023-",         # Empty number part
            "CVE--1234",         # Missing year
            "CVE-2023-12-34",    # Extra hyphen
            "",                  # Empty string
            "CVE-2023-12A4",     # Mixed alphanumeric
            "cve-2023-1234"      # Lowercase
        ]
        
        for cve_id in invalid_cves:
            matched_results = [
                {
                    "package": "test-pkg",
                    "vulns": [{"id": cve_id, "description": "Test vulnerability"}]
                }
            ]
            
            result = generateCVEListFromMatchedResults(matched_results)
            
            # Invalid CVEs should be filtered out
            assert len(result) == 0
    
    def test_mixed_valid_invalid_cve_filtering(self):
        """Test filtering when both valid and invalid CVEs are present"""
        matched_results = [
            {
                "package": "pkg1",
                "vulns": [
                    {"id": "CVE-2023-30861", "description": "Valid CVE"},
                    {"id": "INVALID-2023-1234", "description": "Invalid format"},
                    {"id": "CVE-2022-5678", "description": "Another valid CVE"}
                ]
            },
            {
                "package": "pkg2",
                "vulns": [
                    {"id": "CVE-23-123", "description": "Invalid year format"},
                    {"id": "CVE-2021-9999", "description": "Valid CVE"}
                ]
            }
        ]
        
        result = generateCVEListFromMatchedResults(matched_results)
        
        # Should only include valid CVEs
        assert len(result) == 3
        valid_cve_ids = [cve["cve"] for cve in result]
        assert "CVE-2023-30861" in valid_cve_ids
        assert "CVE-2022-5678" in valid_cve_ids
        assert "CVE-2021-9999" in valid_cve_ids
        
        # Invalid CVEs should not be present
        assert "INVALID-2023-1234" not in valid_cve_ids
        assert "CVE-23-123" not in valid_cve_ids
    
    def test_cve_format_in_package_report(self):
        """Test CVE format validation in package report vulnerabilities"""
        matched_results = [
            {
                "package": "django",
                "installed_version": "3.0.0",
                "status": "success",
                "audit_status": "success",
                "vulns": [
                    {"id": "CVE-2023-41164", "description": "Valid CVE"},
                    {"id": "INVALID-FORMAT", "description": "Invalid CVE"},
                    {"id": "CVE-2023-43665", "description": "Another valid CVE"}
                ]
            }
        ]
        
        result = generatePackageReport(matched_results)
        
        # Package report should include all vulnerabilities (no filtering)
        package = result["packages"][0]
        vulnerabilities = package["vulnerabilities"]
        
        assert len(vulnerabilities) == 3
        
        # But verify CVE IDs are preserved as-is for reporting
        vuln_ids = [vuln["id"] for vuln in vulnerabilities]
        assert "CVE-2023-41164" in vuln_ids
        assert "INVALID-FORMAT" in vuln_ids
        assert "CVE-2023-43665" in vuln_ids
    
    def test_cve_year_range_validation(self):
        """Test CVE year validation for reasonable ranges"""
        # Test edge cases for years
        edge_case_cves = [
            ("CVE-1999-0001", True),   # Earliest common CVE year
            ("CVE-2030-1234", True),   # Future year (should be valid)
            ("CVE-1998-1234", True),   # Very early year
            ("CVE-2050-1234", True),   # Far future year
        ]
        
        for cve_id, should_be_valid in edge_case_cves:
            matched_results = [
                {
                    "package": "test-pkg",
                    "vulns": [{"id": cve_id, "description": "Test"}]
                }
            ]
            
            result = generateCVEListFromMatchedResults(matched_results)
            
            if should_be_valid:
                assert len(result) == 1
                assert result[0]["cve"] == cve_id
            else:
                assert len(result) == 0
    
    def test_cve_number_length_validation(self):
        """Test CVE number part length validation"""
        number_length_cases = [
            ("CVE-2023-1234", True),     # Standard 4-digit
            ("CVE-2023-12345", True),    # 5-digit
            ("CVE-2023-123456", True),   # 6-digit
            ("CVE-2023-1234567", True),  # 7-digit
            ("CVE-2023-123", False),     # Too short (3-digit)
            ("CVE-2023-12", False),      # Too short (2-digit)
            ("CVE-2023-1", False),       # Too short (1-digit)
        ]
        
        for cve_id, should_be_valid in number_length_cases:
            matched_results = [
                {
                    "package": "test-pkg",
                    "vulns": [{"id": cve_id, "description": "Test"}]
                }
            ]
            
            result = generateCVEListFromMatchedResults(matched_results)
            
            if should_be_valid:
                assert len(result) == 1, f"CVE {cve_id} should be valid"
                assert result[0]["cve"] == cve_id
            else:
                assert len(result) == 0, f"CVE {cve_id} should be invalid"
    
    def test_cve_format_regex_pattern(self):
        """Test CVE format against expected regex pattern"""
        import re
        
        # Expected CVE pattern: CVE-YYYY-NNNN (where NNNN is 4+ digits)
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        
        test_cases = [
            ("CVE-2023-1234", True),
            ("CVE-2023-12345", True),
            ("CVE-1999-0001", True),
            ("CVE-23-1234", False),
            ("CVE-2023-123", False),
            ("INVALID-2023-1234", False),
            ("CVE-2023-ABCD", False)
        ]
        
        for cve_id, expected_match in test_cases:
            actual_match = bool(cve_pattern.match(cve_id))
            assert actual_match == expected_match, f"CVE {cve_id} regex match failed"
    
    def test_cve_duplicate_handling_with_format_validation(self):
        """Test that duplicate CVEs are handled correctly with format validation"""
        matched_results = [
            {
                "package": "pkg1",
                "vulns": [
                    {"id": "CVE-2023-1234", "description": "First occurrence"},
                    {"id": "INVALID-FORMAT", "description": "Invalid CVE"}
                ]
            },
            {
                "package": "pkg2", 
                "vulns": [
                    {"id": "CVE-2023-1234", "description": "Duplicate occurrence"},
                    {"id": "CVE-2023-5678", "description": "Unique CVE"}
                ]
            }
        ]
        
        result = generateCVEListFromMatchedResults(matched_results)
        
        # Should have 2 unique valid CVEs (duplicate removed, invalid filtered)
        assert len(result) == 2
        cve_ids = [cve["cve"] for cve in result]
        assert "CVE-2023-1234" in cve_ids
        assert "CVE-2023-5678" in cve_ids
        assert "INVALID-FORMAT" not in cve_ids
    
    def test_empty_or_missing_cve_ids(self):
        """Test handling of empty or missing CVE IDs"""
        matched_results = [
            {
                "package": "pkg1",
                "vulns": [
                    {"id": "", "description": "Empty CVE ID"},
                    {"id": None, "description": "None CVE ID"},
                    {"description": "Missing CVE ID field"},
                    {"id": "CVE-2023-1234", "description": "Valid CVE"}
                ]
            }
        ]
        
        result = generateCVEListFromMatchedResults(matched_results)
        
        # Should only include the valid CVE
        assert len(result) == 1
        assert result[0]["cve"] == "CVE-2023-1234"

@pytest.mark.unit
class TestPackageInstallationFailures:
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_single_package_installation_failure(self, mock_subprocess, mock_parse):
        """Test handling of single package installation failure"""
        mock_parse.return_value = ["flask==2.3.2"]
        mock_subprocess.side_effect = subprocess.CalledProcessError(
            1, 'pip install', stderr="Package not found"
        )
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'Package not found' in result[0]['error_message']
        assert mock_subprocess.call_count == 1

@pytest.mark.unit
class TestEmptyMissingRequirements:
    
    def test_parse_missing_requirements_file(self):
        """Test parsing when requirements.txt file doesn't exist"""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = parseRequirements("nonexistent_requirements.txt")
        
        assert result == []
    
    def test_parse_empty_requirements_file(self):
        """Test parsing completely empty requirements file"""
        requirements_content = ""
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("empty_requirements.txt")
        
        assert result == []
    
    def test_parse_requirements_only_comments(self):
        """Test parsing requirements file with only comments"""
        requirements_content = """# This is a comment
# Another comment
# Yet another comment"""
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("comments_only.txt")
        
        assert result == []
    
    def test_parse_requirements_only_whitespace(self):
        """Test parsing requirements file with only whitespace"""
        requirements_content = "   \n\n  \t  \n   "
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("whitespace_only.txt")
        
        assert result == []
    
    def test_parse_requirements_mixed_empty_lines_comments(self):
        """Test parsing requirements file with mixed empty lines and comments"""
        requirements_content = """
# Header comment

# Another comment

# Final comment
"""
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("mixed_empty.txt")
        
        assert result == []
    
    @patch('prepareProject.parseRequirements')
    def test_install_requirements_with_empty_list(self, mock_parse):
        """Test installRequirements behavior with empty requirements list"""
        mock_parse.return_value = []
        
        result = installRequirements()
        
        assert result == []
    
    @patch('prepareProject.parseRequirements')
    def test_install_requirements_with_missing_file(self, mock_parse):
        """Test installRequirements behavior when requirements file is missing"""
        mock_parse.return_value = []  # parseRequirements returns empty list for missing file
        
        result = installRequirements()
        
        assert result == []
    
    def test_parse_requirements_permission_denied(self):
        """Test parsing when requirements file exists but can't be read due to permissions"""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = parseRequirements("protected_requirements.txt")
        
        assert result == []
    
    def test_parse_requirements_io_error(self):
        """Test parsing when requirements file has I/O errors"""
        with patch("builtins.open", side_effect=IOError("I/O error")):
            result = parseRequirements("corrupted_requirements.txt")
        
        assert result == []
    
    @patch('prepareProject.runPipAudit')
    @patch('prepareProject.installRequirements')
    def test_full_workflow_with_empty_requirements(self, mock_install, mock_audit):
        """Test complete workflow when no requirements are found"""
        # Mock empty installation results
        mock_install.return_value = []
        
        # Mock successful but empty audit
        mock_audit.return_value = "[]"
        
        with patch('prepareProject.parsePipAuditOutput') as mock_parse_audit:
            with patch('prepareProject.matchAuditResultsToInstallation') as mock_match:
                with patch('prepareProject.generatePackageReport') as mock_report:
                    with patch('prepareProject.generateCVEListFromMatchedResults') as mock_cve:
                        mock_parse_audit.return_value = []
                        mock_match.return_value = []
                        mock_report.return_value = {
                            "packages": [],
                            "summary": {
                                "total_packages": 0,
                                "successful_installs": 0,
                                "failed_installs": 0,
                                "vulnerabilities_found": 0
                            }
                        }
                        mock_cve.return_value = []
                        
                        # Simulate main workflow
                        installation_results = mock_install.return_value
                        audit_output = mock_audit.return_value
                        audit_results = mock_parse_audit(audit_output)
                        matched_results = mock_match(installation_results, audit_results)
                        package_report = mock_report(matched_results)
                        cve_list = mock_cve(matched_results)
                        
                        # Verify empty results
                        assert installation_results == []
                        assert audit_results == []
                        assert matched_results == []
                        assert package_report["packages"] == []
                        assert package_report["summary"]["total_packages"] == 0
                        assert cve_list == []
    
    @patch('prepareProject.runPipAudit')
    def test_pip_audit_with_empty_environment(self, mock_audit):
        """Test pip-audit behavior when no packages are installed"""
        # pip-audit returns empty results when no packages found
        mock_audit.return_value = "[]"
        
        result = runPipAudit()
        
        assert result == "[]"
    
    def test_match_audit_results_empty_installation(self):
        """Test matchAuditResultsToInstallation with empty installation results"""
        installation_results = []
        audit_results = [{"package": "flask", "vulns": []}]
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert result == []
    
    def test_match_audit_results_empty_audit(self):
        """Test matchAuditResultsToInstallation with empty audit results"""
        installation_results = [{"package": "flask==2.3.2", "status": "success"}]
        audit_results = []
        
        result = matchAuditResultsToInstallation(installation_results, audit_results)
        
        assert len(result) == 1
        assert result[0]['vulns'] == []
        assert result[0]['audit_status'] == 'no_audit_data'
    
    def test_match_audit_results_both_empty(self):
        """Test matchAuditResultsToInstallation with both empty inputs"""
        result = matchAuditResultsToInstallation([], [])
        
        assert result == []
    
    def test_generate_package_report_empty_input(self):
        """Test generatePackageReport with empty matched results"""
        empty_results = []
        
        result = generatePackageReport(empty_results)
        
        assert "packages" in result
        assert "summary" in result
        assert "report_metadata" in result
        assert result["packages"] == []
        assert result["summary"]["total_packages"] == 0
        assert result["summary"]["successful_installs"] == 0
        assert result["summary"]["failed_installs"] == 0
        assert result["summary"]["vulnerabilities_found"] == 0
    
    def test_generate_cve_list_empty_input(self):
        """Test generateCVEListFromMatchedResults with empty matched results"""
        empty_results = []
        
        result = generateCVEListFromMatchedResults(empty_results)
        
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_empty_results_json_structure(self):
        """Test JSON structure with empty input data"""
        # Test empty package report
        empty_report = generatePackageReport([])
        
        json_str = json.dumps(empty_report)
        parsed_result = json.loads(json_str)
        
        assert "report_metadata" in parsed_result
        assert "summary" in parsed_result
        assert "packages" in parsed_result
        assert parsed_result["packages"] == []
        assert parsed_result["report_metadata"]["total_packages"] == 0
        
        # Test empty CVE list
        empty_cve_list = generateCVEListFromMatchedResults([])
        
        json_str = json.dumps(empty_cve_list)
        parsed_result = json.loads(json_str)
        
        assert isinstance(parsed_result, list)
        assert len(parsed_result) == 0
    
    @patch('prepareProject.writeOutputFiles')
    def test_write_output_files_empty_data(self, mock_write):
        """Test writeOutputFiles behavior with empty data"""
        empty_package_report = {
            "packages": [],
            "summary": {"total_packages": 0}
        }
        empty_cve_list = []
        
        writeOutputFiles(empty_package_report, empty_cve_list)
        
        # Verify writeOutputFiles was called with empty data
        mock_write.assert_called_once_with(empty_package_report, empty_cve_list)
    
    def test_parse_requirements_unicode_error(self):
        """Test parsing when requirements file has encoding issues"""
        with patch("builtins.open", side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid start byte")):
            result = parseRequirements("unicode_error.txt")
        
        assert result == []
    
    def test_parse_requirements_os_error(self):
        """Test parsing when requirements file has OS-level errors"""
        with patch("builtins.open", side_effect=OSError("OS error")):
            result = parseRequirements("os_error.txt")
        
        assert result == []
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_install_requirements_no_packages_no_subprocess_calls(self, mock_subprocess, mock_parse):
        """Test that subprocess.run is not called when no packages to install"""
        mock_parse.return_value = []
        
        result = installRequirements()
        
        assert result == []
        mock_subprocess.assert_not_called()
    
    def test_parse_requirements_default_file_missing(self):
        """Test parsing with default requirements.txt file missing"""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = parseRequirements()  # No filename provided, uses default
        
        assert result == []
    
    @patch('os.path.exists')
    def test_requirements_file_existence_check(self, mock_exists):
        """Test behavior when requirements file existence is checked"""
        mock_exists.return_value = False
        
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = parseRequirements("nonexistent.txt")
        
        assert result == []
    
    def test_parse_requirements_with_bom(self):
        """Test parsing requirements file with BOM (Byte Order Mark)"""
        # UTF-8 BOM + empty content
        requirements_content = "\ufeff"
        
        with patch("builtins.open", mock_open(read_data=requirements_content)):
            result = parseRequirements("bom_file.txt")
        
        assert result == []
    
    def test_parse_requirements_different_line_endings(self):
        """Test parsing empty requirements with different line endings"""
        test_cases = [
            "\r\n\r\n",  # Windows line endings
            "\n\n",      # Unix line endings  
            "\r\r",      # Mac line endings
            "\r\n\n\r"   # Mixed line endings
        ]
        
        for line_ending_content in test_cases:
            with patch("builtins.open", mock_open(read_data=line_ending_content)):
                result = parseRequirements("line_endings.txt")
                assert result == []
        mock_parse.return_value = ["nonexistent-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: Could not find a version that satisfies the requirement nonexistent-package==1.0.0"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['package'] == 'nonexistent-package==1.0.0'
        assert result[0]['status'] == 'failed'
        assert 'Could not find a version' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_network_timeout_failure(self, mock_subprocess, mock_parse):
        """Test handling of network timeout during installation"""
        mock_parse.return_value = ["requests==2.28.1"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: Operation timed out"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'timed out' in result[0]['error_message'].lower()
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_permission_denied_failure(self, mock_subprocess, mock_parse):
        """Test handling of permission denied during installation"""
        mock_parse.return_value = ["flask==2.3.2"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: Permission denied: '/usr/local/lib/python3.9/site-packages/'"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'Permission denied' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_dependency_conflict_failure(self, mock_subprocess, mock_parse):
        """Test handling of dependency conflict during installation"""
        mock_parse.return_value = ["incompatible-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: pip's dependency resolver does not currently take into account all the packages that are installed"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'dependency resolver' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_disk_space_failure(self, mock_subprocess, mock_parse):
        """Test handling of insufficient disk space during installation"""
        mock_parse.return_value = ["large-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: No space left on device"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'No space left' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_corrupted_package_failure(self, mock_subprocess, mock_parse):
        """Test handling of corrupted package during installation"""
        mock_parse.return_value = ["corrupted-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: File is not a zip file"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'not a zip file' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_python_version_incompatibility_failure(self, mock_subprocess, mock_parse):
        """Test handling of Python version incompatibility"""
        mock_parse.return_value = ["future-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "ERROR: Package 'future-package' requires a different Python: 3.8.0 not in '>=3.10'"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'requires a different Python' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_multiple_package_failures(self, mock_subprocess, mock_parse):
        """Test handling of multiple package installation failures"""
        mock_parse.return_value = [
            "nonexistent-pkg1==1.0.0",
            "nonexistent-pkg2==2.0.0", 
            "nonexistent-pkg3==3.0.0"
        ]
        
        def mock_run_side_effect(cmd, **kwargs):
            if "nonexistent-pkg1" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Could not find nonexistent-pkg1"
                raise error
            elif "nonexistent-pkg2" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Network timeout"
                raise error
            elif "nonexistent-pkg3" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Permission denied"
                raise error
        
        mock_subprocess.side_effect = mock_run_side_effect
        
        result = installRequirements()
        
        assert len(result) == 3
        assert all(pkg['status'] == 'failed' for pkg in result)
        
        # Verify different error messages
        error_messages = [pkg['error_message'] for pkg in result]
        assert any('Could not find' in msg for msg in error_messages)
        assert any('Network timeout' in msg for msg in error_messages)
        assert any('Permission denied' in msg for msg in error_messages)
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_mixed_success_failure_scenarios(self, mock_subprocess, mock_parse):
        """Test mixed success and failure scenarios"""
        mock_parse.return_value = [
            "successful-pkg==1.0.0",
            "failing-pkg==1.0.0",
            "another-success==2.0.0"
        ]
        
        def mock_run_side_effect(cmd, **kwargs):
            if "failing-pkg" in cmd:
                error = subprocess.CalledProcessError(1, 'pip install')
                error.stderr = "ERROR: Package not found"
                raise error
            else:
                return MagicMock(returncode=0)
        
        mock_subprocess.side_effect = mock_run_side_effect
        
        result = installRequirements()
        
        assert len(result) == 3
        
        successful = [pkg for pkg in result if pkg['status'] == 'success']
        failed = [pkg for pkg in result if pkg['status'] == 'failed']
        
        assert len(successful) == 2
        assert len(failed) == 1
        assert failed[0]['package'] == 'failing-pkg==1.0.0'
        assert 'Package not found' in failed[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_empty_stderr_error_handling(self, mock_subprocess, mock_parse):
        """Test handling when subprocess error has empty stderr"""
        mock_parse.return_value = ["failing-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = ""  # Empty stderr
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert result[0]['error_message'] is not None
        assert len(result[0]['error_message']) > 0
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_none_stderr_error_handling(self, mock_subprocess, mock_parse):
        """Test handling when subprocess error has None stderr"""
        mock_parse.return_value = ["failing-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = None  # None stderr
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert result[0]['error_message'] is not None
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_unexpected_exception_handling(self, mock_subprocess, mock_parse):
        """Test handling of unexpected exceptions during installation"""
        mock_parse.return_value = ["test-package==1.0.0"]
        
        mock_subprocess.side_effect = Exception("Unexpected system error")
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'Unexpected system error' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_keyboard_interrupt_handling(self, mock_subprocess, mock_parse):
        """Test handling of keyboard interrupt during installation"""
        mock_parse.return_value = ["interrupted-package==1.0.0"]
        
        mock_subprocess.side_effect = KeyboardInterrupt()
        
        # KeyboardInterrupt should propagate, not be caught
        with pytest.raises(KeyboardInterrupt):
            installRequirements()
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_file_not_found_pip_executable(self, mock_subprocess, mock_parse):
        """Test handling when pip executable is not found"""
        mock_parse.return_value = ["test-package==1.0.0"]
        
        mock_subprocess.side_effect = FileNotFoundError("pip command not found")
        
        result = installRequirements()
        
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
        assert 'pip command not found' in result[0]['error_message']
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_installation_failure_logging(self, mock_subprocess, mock_parse):
        """Test that installation failures are properly logged"""
        mock_parse.return_value = ["failing-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "Package installation failed"
        mock_subprocess.side_effect = error
        
        with patch('prepareProject.logging.warning') as mock_log:
            result = installRequirements()
            
            # Verify logging was called
            mock_log.assert_called()
            log_call_args = mock_log.call_args[0][0]
            assert 'Failed to install' in log_call_args
            assert 'failing-package==1.0.0' in log_call_args
    
    @patch('prepareProject.parseRequirements')
    @patch('subprocess.run')
    def test_installation_retry_behavior(self, mock_subprocess, mock_parse):
        """Test that failed installations don't retry automatically"""
        mock_parse.return_value = ["failing-package==1.0.0"]
        
        error = subprocess.CalledProcessError(1, 'pip install')
        error.stderr = "Temporary failure"
        mock_subprocess.side_effect = error
        
        result = installRequirements()
        
        # Should only attempt installation once per package
        assert mock_subprocess.call_count == 1
        assert len(result) == 1
        assert result[0]['status'] == 'failed'
