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
  const [validationResults, setValidationResults] = useState<any | null>(null); // Changed to 'any' to handle JSON
  const [fileType, setFileType] = useState<string>('profile');
  const [operation, setOperation] = useState<string>('validate');
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
    }
  };

  const cleanOutput = (output: string) => {
    // Remove unwanted characters (e.g., ANSI escape codes)
    return output.replace(/[\u001b\u009b][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d\/#&.:=?%@~_]*)*)?\u0007)|(?:(\d{1,4}(?:;\d{0,4})*)?[0-9A-PR-TZcf-ntqry=><~]))/g, '')
                 .replace(/\[m/g, ''); // Additional cleanup if necessary
  };

  const handleUpload = async () => {
    if (selectedFile) {
      setUploading(true);
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('fileType', fileType);
      formData.append('operation', operation);

      console.log('Starting upload request...');
      const startTime = Date.now();

      // Create AbortController for timeout handling
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minutes timeout

      try {
        const response = await fetch(apiEndpoint, {
          method: 'POST',
          body: formData,
          signal: controller.signal,
        });

        clearTimeout(timeoutId); // Clear timeout on successful response
        const endTime = Date.now();
        console.log(`Request completed in ${endTime - startTime}ms`);
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        console.log('Response headers:', [...response.headers.entries()]);

        if (response.ok) {
          const resultText = await response.json();
          console.log('Response data:', resultText);
          setValidationResults(resultText);
          setUploadStatus('File successfully uploaded');
        } else {
          console.log('Response not ok, status:', response.status);
          setUploadStatus('File upload or validation failed');
        }
      } catch (error) {
        clearTimeout(timeoutId); // Clear timeout on error
        const endTime = Date.now();
        console.log(`Request failed after ${endTime - startTime}ms`);

        // Handle different error types
        if (error instanceof Error) {
          console.log('Error type:', error.constructor.name);
          console.log('Error message:', error.message);

          // Check if it's an abort error (timeout)
          if (error.name === 'AbortError') {
            setUploadStatus('Request timed out. The validation is taking longer than expected.');
          } else {
            setUploadStatus('Error uploading or validating file');
          }
        } else {
          console.log('Unknown error:', error);
          setUploadStatus('Error uploading or validating file');
        }
      } finally {
        setUploading(false);
      }
    }
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
              disabled={uploading}
              className={`upload-button ${uploading ? 'disabled' : 'primary'}`}
            >
              {uploading ? 'Uploading...' : 'Upload File'}
            </button>
          </>
        )}
      </div>

      {uploadStatus && (
        <div className={`status-message ${getStatusClass(uploadStatus)}`}>
          {uploadStatus}
        </div>
      )}

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
