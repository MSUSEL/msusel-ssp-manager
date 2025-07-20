import React, { useState, useRef, useEffect } from 'react';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, FileIcon } from '@radix-ui/react-icons';
import './FileUploader.css';

interface FileUploaderProps {
  apiEndpoint: string;
}

const FileUploader: React.FC<FileUploaderProps> = ({ apiEndpoint }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [validationResults, setValidationResults] = useState<any | null>(null);
  const [fileType, setFileType] = useState<string>('profile');
  const [operation, setOperation] = useState<string>('validate');
  const [jobId, setJobId] = useState<string | null>(null); // Store job_id from async response
  const [isProcessing, setIsProcessing] = useState(false); // Track if validation is running
  const [error, setError] = useState<string | null>(null); // Track validation errors
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fileTypes = [
    'catalog', 
    'profile', 
    'component-definition', 
    'ssp', 
    'mapping-collection', 
    'ap', 
    'ar', 
    'poam', 
    'metaschema'
  ];

  const operationsByType: { [key: string]: string[] } = {
    'profile': ['validate', 'convert', 'resolve'],
    'metaschema': ['generate-schema', 'validate'],
    'default': ['validate', 'convert']
  };

  useEffect(() => {
    const availableOperations = operationsByType[fileType] || operationsByType['default'];
    setOperation(availableOperations[0]);
  }, [fileType]);

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setSelectedFile(files[0]);
      setUploadStatus(null); // Clear previous status
      setValidationResults(null); // Clear previous results
      setJobId(null); // Clear previous job_id
      setIsProcessing(false); // Reset processing state
      setError(null); // Clear previous errors
    }
  };

  const cleanOutput = (output: string) => {
    // Remove unwanted characters (e.g., ANSI escape codes)
    return output.replace(/[\u001b\u009b][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(\d{1,4}(?:;\d{0,4})*)?[0-9A-PR-TZcf-ntqry=><~]))/g, '')
                 .replace(/\[m/g, ''); // Additional cleanup if necessary
  };

  // Upload handler following the runTests() pattern from CurrentStatus.tsx
  const handleUpload = async () => {
    if (!selectedFile) return;

    // Prevent multiple simultaneous uploads
    if (uploading || isProcessing) {
      console.log('Upload already in progress, ignoring request');
      return;
    }

    setUploading(true);
    setIsProcessing(true);
    setUploadStatus(null);
    setValidationResults(null);
    setJobId(null);
    setError(null); // Clear previous errors

    console.log('Starting OSCAL validation...');

    try {
      // Step 3.1.1: Modify fetch to expect job_id response instead of validation results
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('fileType', fileType);
      formData.append('operation', operation);

      console.log('Triggering validation execution...');
      console.log('API Endpoint:', apiEndpoint);
      console.log('FormData contents:', {
        file: selectedFile.name,
        fileType: fileType,
        operation: operation
      });

      // Step 3.1.2: Remove existing timeout logic (AbortController, etc.)
      const response = await fetch(apiEndpoint, {
        method: 'POST',
        body: formData,
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      const responseData = await response.json();
      console.log('Validation execution started successfully:', responseData);

      // Step 3.1.3: Store job_id in component state
      if (!responseData.job_id) {
        throw new Error('No job_id received from server');
      }

      setJobId(responseData.job_id);
      console.log('Job ID received:', responseData.job_id);
      setUploadStatus('File uploaded successfully. Processing...');

      // Step 3.2: Start polling for validation results
      console.log('Starting to poll for validation results...');
      try {
        await pollForValidationResults(responseData.job_id);
        console.log('Polling completed successfully');
      } catch (pollError) {
        console.error('Polling failed:', pollError);
        throw pollError;
      }

      setUploading(false); // Upload phase complete, but still processing

    } catch (error) {
      console.error('Error starting validation:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      setError(`Error starting validation: ${errorMessage}`);
      setUploadStatus(null);
      setUploading(false);
      setIsProcessing(false);
      setJobId(null);
    }
  };

  // Polling function that waits for validation completion (copied from CurrentStatus.tsx)
  const pollForValidationResults = async (jobId: string): Promise<void> => {
    const pollInterval = 5000; // Poll every 5 seconds
    const maxPollingTime = 600000; // Maximum 10 minutes of polling
    let pollCount = 0;
    const maxPolls = maxPollingTime / pollInterval;

    console.log('Starting to poll for validation completion...', {
      jobId,
      maxPolls,
      pollInterval,
      maxPollingTime: maxPollingTime / 1000 + ' seconds'
    });

    return new Promise<void>((resolve, reject) => {
      const poll = async (): Promise<void> => {
        pollCount++;
        const elapsedTime = pollCount * pollInterval;

        console.log(`Polling for validation results... attempt ${pollCount}/${maxPolls} (${Math.round(elapsedTime/1000)}s elapsed)`);

        try {
          // Step 3.2.1: Poll /api/validate/status/{job_id} instead of file
          const response = await fetch(`/api/validate/status/${jobId}`, {
            cache: 'no-store',
            headers: {
              'Cache-Control': 'no-cache',
              'Pragma': 'no-cache'
            }
          });

          if (response.ok) {
            const statusData = await response.json();
            console.log('Validation status response:', statusData);

            // Step 3.2.2: Use job status instead of file timestamp logic
            if (statusData.status === 'COMPLETED') {
              console.log('Validation completed! Processing results...');

              // Update UI with results
              setValidationResults(statusData.result);
              setUploadStatus('Validation completed successfully!');
              setIsProcessing(false);

              console.log('Validation results updated successfully');
              resolve();
              return;
            } else if (statusData.status === 'FAILED') {
              console.log('Validation failed:', statusData.result);

              const errorMessage = statusData.result?.message || 'Unknown error';
              setError(`Validation failed: ${errorMessage}`);
              setUploadStatus(null);
              setIsProcessing(false);

              reject(new Error(errorMessage));
              return;
            } else if (statusData.status === 'RUNNING') {
              console.log('Validation still running...');
            } else {
              console.log(`Validation status: ${statusData.status}`);
            }
          } else {
            console.log(`Failed to get validation status (HTTP ${response.status})`);
          }
        } catch (pollError) {
          console.log(`Polling attempt ${pollCount} failed:`, pollError);
        }

        // Continue polling if we haven't exceeded limits
        if (pollCount < maxPolls) {
          setTimeout(poll, pollInterval);
        } else {
          console.log('Polling timeout reached after 10 minutes');
          setError('Validation is taking longer than expected (>10 minutes). Please check the server logs or try again.');
          setUploadStatus(null);
          setIsProcessing(false);
          reject(new Error('Polling timeout after 10 minutes'));
        }
      };

      // Start polling immediately
      poll();
    });
  };

  const getStatusClass = (status: string | null) => {
    if (!status) return '';
    return status.includes('successfully') ? 'status-success' : 'status-error';
  };

  return (
    <div>
      <div style={{ marginBottom: '15px' }}>
        <label htmlFor="fileType" style={{ marginRight: '10px' }}>Document Type:</label>
        <Select.Root onValueChange={(value) => setFileType(value)} value={fileType}>
          <Select.Trigger className="SelectTrigger">
            <Select.Value />
            <Select.Icon>
              <ChevronDownIcon />
            </Select.Icon>
          </Select.Trigger>
          <Select.Content className="SelectContent">
            <Select.Viewport>
              {fileTypes.map((type) => (
                <Select.Item key={type} value={type} className="SelectItem">
                  <Select.ItemText>{type}</Select.ItemText>
                </Select.Item>
              ))}
            </Select.Viewport>
          </Select.Content>
        </Select.Root>
      </div>
      <div style={{ marginBottom: '15px' }}>
        <label htmlFor="operation" style={{ marginRight: '10px' }}>Operation:</label>
        <Select.Root onValueChange={(value) => setOperation(value)} value={operation}>
          <Select.Trigger className="SelectTrigger">
            <Select.Value />
            <Select.Icon>
              <ChevronDownIcon />
            </Select.Icon>
          </Select.Trigger>
          <Select.Content className="SelectContent">
            <Select.Viewport>
              {(operationsByType[fileType] || operationsByType['default']).map((op) => (
                <Select.Item key={op} value={op} className="SelectItem">
                  <Select.ItemText>{op}</Select.ItemText>
                </Select.Item>
              ))}
            </Select.Viewport>
          </Select.Content>
        </Select.Root>
      </div>
      <div className="upload-controls">
        <button
          onClick={handleClick}
          className="upload-button primary"
          disabled={uploading}
        >
          Select File
        </button>
        <input
          type="file"
          ref={fileInputRef}
          style={{ display: 'none' }}
          onChange={handleFileChange}
        />
        
        {selectedFile && (
          <>
            <p className="selected-file">
              <FileIcon /> {selectedFile.name}
            </p>
            <button
              onClick={handleUpload}
              disabled={uploading || isProcessing}
              className={`upload-button ${(uploading || isProcessing) ? 'disabled' : 'primary'}`}
            >
              {uploading ? 'Uploading...' : isProcessing ? 'Processing...' : 'Upload File'}
            </button>
          </>
        )}
      </div>

      {/* Keep the progress spinner */}
      {isProcessing && (
        <div className="validation-running-indicator">
          <div className="loading-spinner"></div>
          <span>
            Validation in progress... This may take a few minutes.
          </span>
        </div>
      )}

      {/* Keep error handling */}
      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      {/* Keep the final results */}
      {validationResults && (
        <div className="results-container">
          <div className="results-header">
            <h3>Processing Results</h3>
          </div>
          
          <div className="results-content">
            <div className="file-info">
              <FileIcon className="file-icon" />
              <strong>{validationResults.fileName}</strong>
            </div>

            <h4>Output</h4>
            <ul className="output-list">
              {validationResults.oscal_processing_output_list?.map((output: string, index: number) => (
                <li key={index} className="output-item">
                  {cleanOutput(output)}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileUploader;
