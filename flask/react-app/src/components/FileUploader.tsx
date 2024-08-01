import React, { useRef } from 'react';
import './UploadFile.css';

const FileUploader: React.FC = () => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      console.log(`Selected file - ${file.name}`);
      // Add logic to handle the file
    }
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div id="fileChooser">
      <button onClick={handleClick}>Select File</button>
      <input
        type="file"
        ref={fileInputRef}
        style={{ display: 'none' }}
        onChange={handleFileChange}
      />
    </div>
  );
};

export default FileUploader;
