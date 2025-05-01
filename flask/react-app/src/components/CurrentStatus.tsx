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
        const controlsResponse = await fetch('/data/NIST_SP-800-53_rev5_catalog.json');
        const controlsData = await controlsResponse.json();

        // Create a lookup object for control details
        const controlDetailsMap: Record<string, any> = {};
        controlsData.forEach((control: any) => {
          controlDetailsMap[control.id] = control;
        });
        setControlDetails(controlDetailsMap);

        // Try to load test results if they exist
        try {
          const testResultsResponse = await fetch('/data/test_results.json');
          const testResultsData = await testResultsResponse.json();
          setTestResults(testResultsData);

          // Set last test run time from the file metadata
          const lastModified = testResultsResponse.headers.get('last-modified');
          if (lastModified) {
            setLastTestRun(new Date(lastModified).toLocaleString());
          }
        } catch (error) {
          console.log('No test results found or error loading them:', error);
          // This is expected if no tests have been run yet
        }
      } catch (error) {
        console.error('Error loading data:', error);
      }
    };

    loadData();
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
      const details = controlDetails[controlId] || { title: 'Unknown Control', family: 'Unknown' };

      return {
        id: controlId,
        title: details.title || 'Unknown Control',
        family: details.family || 'Unknown',
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

        <div className="test-controls">
          <Button
            onClick={runTests}
            disabled={isRunningTests}
            className="run-tests-button"
          >
            {isRunningTests ? 'Running Tests...' : 'Run Tests'}
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
                                {test.message && (
                                  <div className="test-message">
                                    {test.message}
                                  </div>
                                )}
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
