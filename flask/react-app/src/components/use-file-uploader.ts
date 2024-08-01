import { useState } from 'react';

const useFileUploader = () => {
  const [file, setFile] = useState<File | null>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };

  return {
    file,
    handleFileChange,
  };
};

export default useFileUploader;
