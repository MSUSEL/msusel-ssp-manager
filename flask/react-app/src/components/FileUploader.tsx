import React, { useRef, useState } from 'react';
import './UploadFile.css';

interface FileUploaderProps {
  apiEndpoint: string;
}

const FileUploader: React.FC<FileUploaderProps> = ({ apiEndpoint }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setSelectedFile(files[0]);
      setUploadStatus(null); // Clear previous status
    }
  };

  const handleUpload = async () => {
    if (selectedFile) {
      setUploading(true);
      const formData = new FormData();
      formData.append('file', selectedFile);

      try {
        const response = await fetch(apiEndpoint, {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          setUploadStatus('File successfully uploaded');
        } else {
          setUploadStatus('File upload failed');
        }
      } catch (error) {
        setUploadStatus('Error uploading file');
      } finally {
        setUploading(false);
      }
    }
  };

  return (
    <div>
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
    </div>
  );
};

export default FileUploader;
