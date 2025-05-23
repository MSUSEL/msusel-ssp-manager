import React, { useState, useRef } from 'react';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon } from '@radix-ui/react-icons';
import './FileUploader.css';

interface TestDepnRequestProps {
  apiEndpoint: string;
}

const TestDepnRequest: React.FC<TestDepnRequestProps> = ({ apiEndpoint }) => {
  const [output, setOutput] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [vulnerabilityEffectivenessResults, setvulnerabilityEffectivenessResults] = useState<any | null>(null); // Changed to 'any' to handle JSON
  const [fileType, setFileType] = useState<string>('profile');
  const fileInputRef = useRef<HTMLInputElement>(null);


  const fileTypes = [
    'controls'
  ];

  const handleClick = () => {
    fileInputRef.current?.click();
  };


  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setSelectedFile(files[0]);
      setUploadStatus(null); // Clear previous status
      setvulnerabilityEffectivenessResults(null); // Clear previous results
    }
  };



  const handleUpload = async () => {
    if (selectedFile) {
      setUploading(true);
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('fileType', fileType);

      try {
        const response = await fetch(apiEndpoint, {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          const resultText = await response.json(); // Parse JSON response
          setvulnerabilityEffectivenessResults(resultText);
          setUploadStatus('File successfully uploaded');
        } else {
          setUploadStatus('File upload or validation failed');
        }
      } catch (error) {
        setUploadStatus('Error uploading or validating file');
      } finally {
        setUploading(false);
      }
    }
  };

  return (
    <div className="test-dependencies-container">
      <div className="dependencies-card">
        <div className="dependencies-header">
          <h3>Test Dependencies</h3>
          <p></p>
        </div>

        <div className="dependencies-features">
          <div className="feature-item">
            <div className="feature-text">
              <h4>Reachability Analysis</h4>
              <p>Find reachable security weaknesses in your dependencies</p>
            </div>
          </div>
        </div>

        <div className="file-selection-container">
          <button
            onClick={handleClick}
            className="control-button"
          >
            <span>📄</span> Select Implemented Controls
          </button>
          <input
            type="file"
            ref={fileInputRef}
            style={{ display: 'none' }}
            onChange={handleFileChange}
          />

          {selectedFile && (
            <div className="selected-file-info">
              <span className="file-icon">📄</span> {selectedFile.name}
              <button
                onClick={handleUpload}
                disabled={uploading}
                className={`upload-button ${uploading ? 'disabled' : ''}`}
              >
                {uploading ? 'Uploading...' : 'Analyze Controls'}
              </button>
            </div>
          )}
        </div>

        {uploadStatus && <div className="status-message">{uploadStatus}</div>}

        {vulnerabilityEffectivenessResults && (
          <div className="results-container">
            <h3>Vulnerability Analysis Results</h3>
            <div className="results-content">
              <h4>Findings:</h4>
              <div className="results-message">
                {vulnerabilityEffectivenessResults.message}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TestDepnRequest;
