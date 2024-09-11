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
    <div>
      <button
        onClick={handleClick}
        style={{ 
          backgroundColor: '#007bff', 
          color: 'white', 
          padding: '10px 20px', 
          border: 'none', 
          borderRadius: '4px', 
          cursor: 'pointer',
          marginRight: '10px'
        }}
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
          <p>File selected: {selectedFile.name}</p>
          <button
            onClick={handleUpload}
            disabled={uploading}
            style={{
              backgroundColor: uploading ? '#6c757d' : '#007bff',
              color: 'white',
              padding: '10px 20px',
              border: 'none',
              borderRadius: '4px',
              cursor: uploading ? 'not-allowed' : 'pointer'
            }}
          >
            {uploading ? 'Uploading...' : 'Upload File'}
          </button>
        </>
      )}
      {uploadStatus && <p>{uploadStatus}</p>}
        {vulnerabilityEffectivenessResults && (
        <div style={{ marginTop: '20px', padding: '10px', border: '1px solid #ccc', borderRadius: '5px' }}>
          <h3>Vulnerability Effectiveness Results:</h3>
          <h4>Output:</h4>
          <ul style={{ listStyleType: 'disc', marginLeft: '20px', marginBottom: '10px' }}>
            {vulnerabilityEffectivenessResults.message}
          </ul>
        </div>
      )}
      </div>
  );
};

export default TestDepnRequest;
