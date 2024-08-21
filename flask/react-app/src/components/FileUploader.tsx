import React, { useState, useRef, useEffect } from 'react';

interface FileUploaderProps {
  apiEndpoint: string;
}

const FileUploader: React.FC<FileUploaderProps> = ({ apiEndpoint }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [validationResults, setValidationResults] = useState<string | null>(null);
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

  const handleUpload = async () => {
    if (selectedFile) {
      setUploading(true);
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('fileType', fileType);
      formData.append('operation', operation);

      try {
        const response = await fetch(apiEndpoint, {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          const resultText = await response.text(); // Assuming the backend returns text
          setValidationResults(resultText);
          setUploadStatus('File successfully uploaded and validated');
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
      <div>
        <label htmlFor="fileType">Document Type:</label>
        <select id="fileType" value={fileType} onChange={(e) => setFileType(e.target.value)}>
          {fileTypes.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="operation">Operation:</label>
        <select id="operation" value={operation} onChange={(e) => setOperation(e.target.value)}>
          {(operationsByType[fileType] || operationsByType['default']).map((op) => (
            <option key={op} value={op}>{op}</option>
          ))}
        </select>
      </div>
      <button onClick={handleClick}>Select File</button>
      <input
        type="file"
        ref={fileInputRef}
        style={{ display: 'none' }}
        onChange={handleFileChange}
      />
      {selectedFile && (
        <>
          <p>File selected: {selectedFile.name}</p>
          <button onClick={handleUpload} disabled={uploading}>
            {uploading ? 'Uploading...' : 'Upload File'}
          </button>
        </>
      )}
      {uploadStatus && <p>{uploadStatus}</p>}
      {validationResults && (
        <div style={{ marginTop: '20px', padding: '10px', border: '1px solid #ccc', borderRadius: '5px' }}>
          <h3>Validation Results:</h3>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{validationResults}</pre>
        </div>
      )}
    </div>
  );
};

export default FileUploader;
