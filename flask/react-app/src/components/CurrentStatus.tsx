import React, { useState, useEffect, useMemo } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@radix-ui/react-tabs';
import { Button, Flex, Box, Text, Badge } from '@radix-ui/themes';
import './CurrentStatus.css';
import axios from 'axios';

// Import YAML parser
import yaml from 'js-yaml';

// Define interfaces for our data structures
interface Control {
  id: string;
  title: string;
  family: string;
  status: 'passed' | 'failed' | 'not-tested' | 'not-implemented';
}

interface ImplementedControl {
  uuid: string;
  'control-id': string;
  'by-components': {
    'component-uuid': string;
    uuid: string;
    description: string;
  }[];
}

interface TestResult {
  control_id: string;
  status: 'passed' | 'failed' | 'not-tested';
  test_results: {
    test_name: string;
    status: 'passed' | 'failed';
    message?: string;
  }[];
}

import catalogData from '../data/NIST_SP-800-53_rev5_catalog.json';

const CurrentStatus: React.FC = () => {
  // State for our data
  const [requiredControls, setRequiredControls] = useState<string[]>([]);
  const [implementedControls, setImplementedControls] = useState<ImplementedControl[]>([]);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [controlDetails, setControlDetails] = useState<Record<string, any>>({});
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFamily, setSelectedFamily] = useState<string>('');
  const [isRunningTests, setIsRunningTests] = useState(false);
  const [lastTestRun, setLastTestRun] = useState<string | null>(null);
  const [profileLastModified, setProfileLastModified] = useState<string | null>(null);
  const [sspLastModified, setSspLastModified] = useState<string | null>(null);

  // Add a function to check file modification times
  const checkFileModifications = async () => {
    try {
      console.log("Checking file modifications..."); // Add debug log
      
      // Check profile modification time
      const profileResponse = await fetch('/data/profile.yaml', { method: 'HEAD', cache: 'no-store' });
      const profileModified = profileResponse.headers.get('last-modified');
      if (profileModified) {
        console.log("Profile last modified:", new Date(profileModified).toLocaleString());
        setProfileLastModified(new Date(profileModified).toLocaleString());
      }

      // Check SSP modification time
      const sspResponse = await fetch('/data/ssp.yaml', { method: 'HEAD', cache: 'no-store' });
      const sspModified = sspResponse.headers.get('last-modified');
      if (sspModified) {
        console.log("SSP last modified:", new Date(sspModified).toLocaleString());
        setSspLastModified(new Date(sspModified).toLocaleString());
      }
    } catch (error) {
      console.error('Error checking file modifications:', error);
    }
  };

  // Add an effect to log when testResults changes
  useEffect(() => {
    console.log('testResults state changed:', testResults);
  }, [testResults]);

  // Load the required data
  useEffect(() => {
    const loadData = async () => {
      try {
        // Load profile (required controls)
        const profileResponse = await fetch('/data/profile.yaml');
        const profileYaml = await profileResponse.text();
        const profileData = yaml.load(profileYaml) as any;

        if (profileData?.profile?.imports?.[0]?.['include-controls']?.[0]?.['with-ids']) {
          setRequiredControls(profileData.profile.imports[0]['include-controls'][0]['with-ids']);
        }

        // Load SSP (implemented controls)
        const sspResponse = await fetch('/data/ssp.yaml');
        const sspYaml = await sspResponse.text();
        const sspData = yaml.load(sspYaml) as any;

        if (sspData?.['system-security-plan']?.['control-implementation']?.['implemented-requirements']) {
          setImplementedControls(sspData['system-security-plan']['control-implementation']['implemented-requirements']);
        }

        // Load control details (for families, titles, etc.)
        try {
          console.log('Loading control details from imported catalog...');
          const controlsData = catalogData;
          console.log('Control details data type:', typeof controlsData);
          console.log('Control details is array:', Array.isArray(controlsData));

          if (Array.isArray(controlsData)) {
            console.log('Control details array length:', controlsData.length);
            if (controlsData.length > 0) {
              console.log('First control:', controlsData[0]);
            }
          } else {
            console.error('Control details is not an array:', controlsData);
          }

          // Create a lookup object for control details
          const controlDetailsMap: Record<string, any> = {};
          if (Array.isArray(controlsData)) {
            controlsData.forEach((control: any, index: number) => {
              if (control && typeof control === 'object' && 'id' in control) {
                controlDetailsMap[control.id] = control;
                controlDetailsMap[control.id.toLowerCase()] = control;
              } else {
                console.warn('Invalid control object at index', index, control);
              }
            });
            console.log('Control details map created with', Object.keys(controlDetailsMap).length, 'entries');
          }
          setControlDetails(controlDetailsMap);
        } catch (error) {
          console.error('Error loading control details:', error);
        }

        // Try to load test results if they exist
        try {
          const testResultsResponse = await fetch('/data/test_results.json');
          const testResultsData = await testResultsResponse.json();
          
          // Check if the new format with metadata is used
          if (testResultsData.metadata && testResultsData.results) {
            setTestResults(testResultsData.results);
            setLastTestRun(new Date(testResultsData.metadata.generated_at).toLocaleString());
          } else {
            // Legacy format without metadata
            setTestResults(testResultsData);
            
            // Set last test run time from the file metadata
            const lastModified = testResultsResponse.headers.get('last-modified');
            if (lastModified) {
              setLastTestRun(new Date(lastModified).toLocaleString());
            }
          }
        } catch (error) {
          console.log('No test results found or error loading them:', error);
          // This is expected if no tests have been run yet
        }

        // Add call to check file modifications
        await checkFileModifications();
      } catch (error) {
        console.error('Error loading data:', error);
      }
    };

    loadData();

    // Set up a periodic check for file modifications
    const intervalId = setInterval(checkFileModifications, 30000); // Check every 30 seconds

    // Clean up the interval when the component unmounts
    return () => clearInterval(intervalId);
  }, []);

  // Get unique families from the control details
  const families = useMemo(() => {
    const uniqueFamilies = new Set<string>();

    Object.values(controlDetails).forEach((control: any) => {
      if (control.family) {
        uniqueFamilies.add(control.family);
      }
    });

    return Array.from(uniqueFamilies).sort();
  }, [controlDetails]);

  // Combine all data to create a list of controls with their status
  const controls = useMemo(() => {
    console.log('controls useMemo running with testResults:', testResults); // Debug log

    return requiredControls.map(controlId => {
      // Find if the control is implemented
      const implemented = implementedControls.find(
        impl => impl['control-id'].toLowerCase() === controlId.toLowerCase()
      );

      // Find test results for this control
      const testResult = testResults.find(
        result => result.control_id.toLowerCase() === controlId.toLowerCase()
      );

      if (testResult) {
        console.log(`Found test result for ${controlId}:`, testResult); // Debug log
      } else {
        console.log(`No test result found for ${controlId}`); // Debug log
      }

      // Determine status
      let status: 'passed' | 'failed' | 'not-tested' | 'not-implemented' = 'not-implemented';

      if (implemented) {
        if (testResult) {
          status = testResult.status;
        } else {
          status = 'not-tested';
        }
      }

      // Get control details
      const normalizedControlId = controlId.toLowerCase();
      let details = controlDetails[controlId] || controlDetails[normalizedControlId] || { title: 'Unknown Control', family: 'Unknown' };

      return {
        id: controlId,
        title: details.title || 'Unknown Control',
        status,
        implemented,
        testResult
      };
    });
  }, [requiredControls, implementedControls, testResults, controlDetails]);

  // Filter controls based on search term and selected family
  const filteredControls = useMemo(() => {
    return controls.filter(control => {
      const matchesSearch =
        control.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.title.toLowerCase().includes(searchTerm.toLowerCase());

      if (selectedFamily) {
        return matchesSearch && control.family === selectedFamily;
      }
      return matchesSearch;
    });
  }, [controls, searchTerm, selectedFamily]);

  // Group controls by status for summary
  const statusSummary = useMemo(() => {
    const summary = {
      passed: 0,
      failed: 0,
      'not-tested': 0,
      'not-implemented': 0,
      total: controls.length
    };

    controls.forEach(control => {
      summary[control.status]++;
    });

    return summary;
  }, [controls]);

  // Toggle expanded control
  const toggleControl = (controlId: string) => {
    setExpandedControl(expandedControl === controlId ? null : controlId);

    // Debug: Log the control's test results when expanded
    if (expandedControl !== controlId) {
      const control = controls.find(c => c.id === controlId);
      console.log(`Expanded control ${controlId} test results:`, control?.testResult);
    }
  };

  // Run InSpec tests
  const runTests = async () => {
    setIsRunningTests(true);

    try {
      // Call the backend API to run tests
      const response = await axios.post('/api/run-tests');
      console.log('API response:', response.data);

      if (response.status === 200) {
        // Reload test results
        const testResultsResponse = await fetch('/data/test_results.json');
        const testResultsData = await testResultsResponse.json();
        console.log('Fetched test results:', testResultsData); // Debug log

        // Check the structure of the test results
        if (Array.isArray(testResultsData)) {
          console.log(`Test results is an array with ${testResultsData.length} items`);
          if (testResultsData.length > 0) {
            console.log('First test result:', testResultsData[0]);
            console.log('Expected properties:',
              'control_id' in testResultsData[0],
              'status' in testResultsData[0],
              'test_results' in testResultsData[0]
            );
          }
        } else {
          console.log('Test results is not an array:', typeof testResultsData);
        }

        setTestResults(testResultsData);
        console.log('After setTestResults, current state:', testResults);

        // Update last test run time
        setLastTestRun(new Date().toLocaleString());
      }
    } catch (error) {
      console.error('Error running tests:', error);
      alert('Error running tests. Please check the console for details.');
    } finally {
      setIsRunningTests(false);
    }
  };

  // Get status badge color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'passed':
        return 'green';
      case 'failed':
        return 'red';
      case 'not-tested':
        return 'yellow';
      case 'not-implemented':
        return 'gray';
      default:
        return 'gray';
    }
  };

  // Get status text
  const getStatusText = (status: string) => {
    switch (status) {
      case 'passed':
        return 'Passed';
      case 'failed':
        return 'Failed';
      case 'not-tested':
        return 'Not Tested';
      case 'not-implemented':
        return 'Not Implemented';
      default:
        return 'Unknown';
    }
  };

  // Format failure message to be more user-friendly
  const formatFailureMessage = (message: string): string => {
    // Default case - just clean up the message a bit
    return message
      .replace(/\(compared using ==\)/g, '')
      .replace(/\n/g, ' ')
      .trim();
  };

  // Provide remediation advice based on control ID and test name
  const getRemediationAdvice = (controlId: string, testName: string): string => {
    // Map of control IDs to remediation advice
    const remediationMap: Record<string, string> = {
      'ac-2': 'Review account management settings and ensure proper role-based access controls are implemented.',
      'ac-3': 'Check time-based access restrictions and ensure they are properly enforced in the authorization policy.',
      'ac-4': 'Verify information flow control mechanisms are properly configured and enforced.',
      'ac-5': 'Ensure separation of duties is properly implemented and enforced.',
      'au-2': 'Review audit logging configuration to ensure all required events are being captured.',
      'au-3': 'Verify audit records contain all required content fields.',
      'au-6': 'Ensure audit review, analysis, and reporting processes are in place.',
      'ia-2': 'Verify multi-factor authentication is properly implemented and enforced.',
      'ia-5': 'Review password complexity and management settings.',
      'sc-8': 'Ensure transmission confidentiality and integrity using approved cryptographic mechanisms.',
      'si-3': 'Ensure malicious code protection mechanisms are properly implemented and updated regularly.',
      'si-10': 'Verify input validation is properly implemented for all system inputs.'
    };

    // More specific advice based on test name
    if (testName.includes('outside business hours')) {
      return 'Configure the time-based access control policy to properly restrict access outside of authorized hours.';
    }

    if (testName.includes('multi-factor')) {
      return 'Ensure multi-factor authentication is properly configured and enforced for all privileged accounts.';
    }

    if (testName.includes('audit')) {
      return 'Review audit logging configuration and ensure all required events are being captured with the necessary detail.';
    }

    // Default to the general advice for the control
    return remediationMap[controlId] || 'Review the control implementation and ensure it meets all requirements.';
  };

  return (
    <div className="status-container">
      <div className="status-header">
        <h1>Security Controls Status</h1>

        <div className="status-summary">
          <div className="summary-item">
            <span className="status-dot passed"></span>
            <span>Passed: {statusSummary.passed}</span>
          </div>
          <div className="summary-item">
            <span className="status-dot failed"></span>
            <span>Failed: {statusSummary.failed}</span>
          </div>
          <div className="summary-item">
            <span className="status-dot not-tested"></span>
            <span>Not Tested: {statusSummary['not-tested']}</span>
          </div>
          <div className="summary-item">
            <span className="status-dot not-implemented"></span>
            <span>Not Implemented: {statusSummary['not-implemented']}</span>
          </div>
          <div className="summary-item total">
            <span>Total: {statusSummary.total}</span>
          </div>
        </div>

        <div className="file-timestamps">
          {profileLastModified && (
            <div className="timestamp-item">
              <span className="timestamp-label">Profile Last Modified:</span>
              <span className="timestamp-value">{profileLastModified}</span>
            </div>
          )}
          {sspLastModified && (
            <div className="timestamp-item">
              <span className="timestamp-label">SSP Last Modified:</span>
              <span className="timestamp-value">{sspLastModified}</span>
            </div>
          )}
          {lastTestRun && (
            <div className="timestamp-item">
              <span className="timestamp-label">Last Test Run:</span>
              <span className="timestamp-value">{lastTestRun}</span>
            </div>
          )}
        </div>

        <div className="test-controls">
          <Button
            onClick={runTests}
            disabled={isRunningTests}
            className="run-tests-button"
          >
            {isRunningTests ? 'Running Tests...' : 'Run Tests'}
          </Button>
          <Button
            onClick={() => {
              console.log("Refresh button clicked");
              checkFileModifications();
            }}
            className="refresh-button"
          >
            Refresh File Status
          </Button>
          {lastTestRun && (
            <div className="last-run">
              Last test run: {lastTestRun}
            </div>
          )}
        </div>

        <div className="search-filter-container">
          <input
            type="text"
            placeholder="Search by control ID or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          <select
            value={selectedFamily}
            onChange={(e) => setSelectedFamily(e.target.value)}
            className="family-select"
          >
            <option value="">All Families</option>
            {families.map(family => (
              <option key={family} value={family}>{family}</option>
            ))}
          </select>
        </div>

        {searchTerm && (
          <div className="search-results-count">
            Found {filteredControls.length} controls
          </div>
        )}
      </div>

      <div className="controls-list">
        {filteredControls.map((control) => (
          <div key={control.id} className="control-section">
            <div
              className={`control-header ${expandedControl === control.id ? 'expanded' : ''}`}
              onClick={() => toggleControl(control.id)}
            >
              <div className="control-title">
                <span className="control-family">{control.family}</span>
                <h2>{control.id} - {control.title}</h2>
              </div>
              <div className="control-status">
                <span className={`status-indicator ${control.status}`}>
                  {getStatusText(control.status)}
                </span>
                <span className="expand-icon">{expandedControl === control.id ? '−' : '+'}</span>
              </div>
            </div>

            {expandedControl === control.id && (
              <div className="control-details">
                <Tabs defaultValue="implementation">
                  <TabsList>
                    <TabsTrigger value="implementation">Implementation</TabsTrigger>
                    <TabsTrigger value="test-results">Test Results</TabsTrigger>
                  </TabsList>

                  <TabsContent value="implementation">
                    <div className="implementation-section">
                      {control.implemented ? (
                        <>
                          <h3>Implementation Description</h3>
                          <p>{control.implemented['by-components'][0]?.description || 'No implementation details provided.'}</p>
                        </>
                      ) : (
                        <p className="not-implemented-message">This control has not been implemented yet.</p>
                      )}
                    </div>
                  </TabsContent>

                  <TabsContent value="test-results">
                    <div className="test-results-section">
                      {control.testResult ? (
                        <>
                          <h3>Test Results</h3>
                          <div className="test-result-summary">
                            <Badge color={getStatusColor(control.status)}>
                              {getStatusText(control.status)}
                            </Badge>
                          </div>

                          <h4>Individual Tests</h4>
                          <ul className="test-results-list">
                            {control.testResult.test_results.map((test, index) => (
                              <li key={index} className={`test-result ${test.status}`}>
                                <div className="test-result-header">
                                  <span className="test-name">{test.test_name}</span>
                                  <Badge color={test.status === 'passed' ? 'green' : 'red'}>
                                    {test.status === 'passed' ? 'Passed' : 'Failed'}
                                  </Badge>
                                </div>
                              </li>
                            ))}
                          </ul>
                        </>
                      ) : (
                        <p className="not-tested-message">
                          {control.implemented
                            ? 'This control has been implemented but not tested yet.'
                            : 'This control has not been implemented or tested yet.'}
                        </p>
                      )}
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default CurrentStatus;
