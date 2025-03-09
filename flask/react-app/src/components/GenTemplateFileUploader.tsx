import React, { useState, useRef } from 'react';
import * as Select from '@radix-ui/react-select';
import { ChevronDownIcon, FileIcon } from '@radix-ui/react-icons';
import './FileUploader.css';

interface FileUploaderProps {
  apiEndpoint: string;
}

const GenTemplateFileUploader: React.FC<FileUploaderProps> = ({ apiEndpoint }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [generationtionResults, setGenerationtionResults] = useState<any | null>(null);
  const [fileType, setFileType] = useState<string>('profile');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fileTypes = ['profile'];

  const getStatusClass = (status: string | null) => {
    if (!status) return '';
    return status.includes('successfully') ? 'status-success' : 'status-error';
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setSelectedFile(files[0]);
      setUploadStatus(null);
      setGenerationtionResults(null);
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
          const resultText = await response.json();
          setGenerationtionResults(resultText);
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
      <div className="select-container">
        <label htmlFor="fileType" className="select-label">Document Type:</label>
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

      {generationtionResults && (
        <div className="results-container">
          <div className="results-header">
            <h3>Processing Results</h3>
          </div>
          
          <div className="results-content">
            <div className="file-info">
              <FileIcon className="file-icon" />
              <strong>{selectedFile?.name}</strong>
            </div>

            <h4>Output</h4>
            <div className="output-item">
              {generationtionResults.message}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GenTemplateFileUploader;
