import React, { useState, useRef } from 'react';
import { Box, Button, Text, Flex, Card, Code } from '@radix-ui/themes';
import { FileIcon, UploadIcon } from '@radix-ui/react-icons';
import './CveCweUpload.css';

// Interface for component props
interface CveCweUploadProps {
  onUploadSuccess?: (data: any) => void;
  onUploadError?: (error: string) => void;
}

// Interface for upload response data
interface UploadResponse {
  message: string;
  filename: string;
  data_type: 'cve' | 'cwe';
  item_count: number;
  processing_status: string;
  graph_data?: any;
  priority_controls?: any;
  attack_paths?: any;
  warning?: string;
}

// Interface for component state
interface UploadState {
  selectedFile: File | null;
  uploading: boolean;
  uploadStatus: string | null;
  uploadResults: UploadResponse | null;
  error: string | null;
}

const CveCweUpload: React.FC<CveCweUploadProps> = ({ 
  onUploadSuccess, 
  onUploadError 
}) => {
  // Component state
  const [state, setState] = useState<UploadState>({
    selectedFile: null,
    uploading: false,
    uploadStatus: null,
    uploadResults: null,
    error: null
  });

  // File input reference
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Handle file selection
  const handleFileSelect = () => {
    fileInputRef.current?.click();
  };

  // Client-side validation function
  const validateFile = async (file: File): Promise<{ isValid: boolean; error?: string; dataType?: 'cve' | 'cwe' }> => {
    try {
      // Validate file extension
      if (!file.name.toLowerCase().endsWith('.json')) {
        return { isValid: false, error: 'File must have .json extension' };
      }

      // Read and parse JSON content
      const fileContent = await file.text();
      let data: any;

      try {
        data = JSON.parse(fileContent);
      } catch (jsonError) {
        return { isValid: false, error: 'Invalid JSON format' };
      }

      // Validate array structure
      if (!Array.isArray(data)) {
        return { isValid: false, error: 'Data must be an array of objects' };
      }

      if (data.length === 0) {
        return { isValid: false, error: 'Data array cannot be empty' };
      }

      // Check if all items are objects
      if (!data.every(item => typeof item === 'object' && item !== null)) {
        return { isValid: false, error: 'All items must be objects' };
      }

      // Detect and validate format
      const firstItem = data[0];

      if ('cve' in firstItem) {
        // Validate CVE format
        const cvePattern = /^CVE-\d{4}-\d{4,}$/;
        for (const item of data) {
          if (!('cve' in item)) {
            return { isValid: false, error: 'All items must have "cve" key for CVE format' };
          }
          if (!cvePattern.test(item.cve)) {
            return { isValid: false, error: `Invalid CVE format: ${item.cve}. Expected format: CVE-YYYY-NNNN` };
          }
        }
        return { isValid: true, dataType: 'cve' };
      } else if ('cwe' in firstItem) {
        // Validate CWE format
        for (const item of data) {
          if (!('cwe' in item)) {
            return { isValid: false, error: 'All items must have "cwe" key for CWE format' };
          }
          if (isNaN(Number(item.cwe))) {
            return { isValid: false, error: `Invalid CWE format: ${item.cwe}. Expected numeric value` };
          }
        }
        return { isValid: true, dataType: 'cwe' };
      } else {
        return { isValid: false, error: 'Data must contain either "cve" or "cwe" keys' };
      }
    } catch (error) {
      return { isValid: false, error: 'Error reading file content' };
    }
  };

  // Handle file change with validation
  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Clear previous state
    setState(prev => ({
      ...prev,
      selectedFile: null,
      uploadStatus: null,
      uploadResults: null,
      error: null
    }));

    // Validate file
    const validation = await validateFile(file);

    if (validation.isValid) {
      setState(prev => ({
        ...prev,
        selectedFile: file,
        uploadStatus: `Valid ${validation.dataType?.toUpperCase()} file selected`,
        error: null
      }));
    } else {
      setState(prev => ({
        ...prev,
        selectedFile: null,
        error: validation.error || 'File validation failed'
      }));
    }
  };

  // Handle file upload
  const handleUpload = async () => {
    if (!state.selectedFile) return;

    // Prevent multiple simultaneous uploads
    if (state.uploading) {
      console.log('Upload already in progress, ignoring request');
      return;
    }

    setState(prev => ({
      ...prev,
      uploading: true,
      uploadStatus: null,
      uploadResults: null,
      error: null
    }));

    try {
      // Create FormData for file upload
      const formData = new FormData();
      formData.append('file', state.selectedFile);

      console.log('Starting CVE/CWE upload...', {
        filename: state.selectedFile.name,
        size: state.selectedFile.size
      });

      // Make HTTP POST request to backend
      const response = await fetch('/api/cve-cwe-mappings/upload', {
        method: 'POST',
        body: formData,
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      const responseData: UploadResponse = await response.json();
      console.log('Upload successful:', responseData);

      // Store results in localStorage for persistence across navigation
      const uploadData = {
        timestamp: new Date().toISOString(),
        filename: responseData.filename,
        data_type: responseData.data_type,
        item_count: responseData.item_count,
        graph_data: responseData.graph_data,
        priority_controls: responseData.priority_controls,
        attack_paths: responseData.attack_paths,
        warning: responseData.warning
      };

      localStorage.setItem('cve_cwe_upload_results', JSON.stringify(uploadData));
      console.log('CVE/CWE upload results stored in localStorage:', uploadData);

      // Update state with success
      setState(prev => ({
        ...prev,
        uploading: false,
        uploadResults: responseData,
        uploadStatus: responseData.warning
          ? `Upload successful with warnings: ${responseData.warning}`
          : `Successfully processed ${responseData.item_count} ${responseData.data_type.toUpperCase()} entries`,
        error: null
      }));

      // Call success callback if provided
      if (onUploadSuccess) {
        onUploadSuccess(responseData);
      }

    } catch (error) {
      console.error('Upload failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';

      setState(prev => ({
        ...prev,
        uploading: false,
        uploadResults: null,
        error: errorMessage
      }));

      // Call error callback if provided
      if (onUploadError) {
        onUploadError(errorMessage);
      }
    }
  };

  return (
    <Box className="cve-cwe-upload-container">
      <Flex direction="column" gap="3">
        <Text size="4" weight="bold">
          CVE/CWE Upload
        </Text>
        
        <Text size="2" color="gray">
          Upload a JSON file containing CVE or CWE identifiers for analysis.
        </Text>

        {/* Format requirements */}
        <Card>
          <Flex direction="column" gap="2">
            <Text size="3" weight="medium">Format Requirements:</Text>
            <Text size="2">
              <strong>CVE Format:</strong>
            </Text>
            <Code size="1">
              [{"{"}"cve": "CVE-2000-0114"{"}"}, {"{"}"cve": "CVE-2001-0537"{"}"}]
            </Code>
            <Text size="2">
              <strong>CWE Format:</strong>
            </Text>
            <Code size="1">
              [{"{"}"cwe": "5"{"}"}, {"{"}"cwe": "6"{"}"}]
            </Code>
            <Text size="1" color="gray">
              Files must contain either CVEs OR CWEs, never mixed.
            </Text>
          </Flex>
        </Card>

        {/* File upload interface */}
        <Box className="file-upload-section">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".json"
            style={{ display: 'none' }}
          />

          <Button
            onClick={handleFileSelect}
            disabled={state.uploading}
            size="3"
            variant="outline"
          >
            <UploadIcon />
            Select JSON File
          </Button>

          {/* Show selected filename */}
          {state.selectedFile && (
            <Flex align="center" gap="2" mt="2">
              <FileIcon />
              <Text size="2" weight="medium">
                {state.selectedFile.name}
              </Text>
              <Text size="1" color="gray">
                ({Math.round(state.selectedFile.size / 1024)} KB)
              </Text>
            </Flex>
          )}

          {/* Upload button */}
          {state.selectedFile && (
            <Button
              onClick={handleUpload}
              disabled={state.uploading}
              size="3"
              mt="2"
            >
              {state.uploading ? 'Processing...' : 'Upload and Analyze'}
            </Button>
          )}
        </Box>

        {/* Loading indicator */}
        {state.uploading && (
          <Box className="loading-indicator" p="3" style={{ backgroundColor: '#f0f8ff', borderRadius: '6px' }}>
            <Flex align="center" gap="2">
              <div style={{
                width: '16px',
                height: '16px',
                border: '2px solid #e0e0e0',
                borderTop: '2px solid #007acc',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
              <Text size="2" color="blue" weight="medium">
                Processing CVE/CWE data... This may take a moment.
              </Text>
            </Flex>
          </Box>
        )}

        {/* Status display */}
        {state.uploadStatus && (
          <Box className="status-message" p="3" style={{ backgroundColor: '#e8f5e8', borderRadius: '6px' }}>
            <Text size="2" color="green" weight="medium">{state.uploadStatus}</Text>
          </Box>
        )}

        {/* Error display */}
        {state.error && (
          <Box className="error-message" p="3" style={{ backgroundColor: '#ffeaea', borderRadius: '6px' }}>
            <Text size="2" color="red" weight="medium">{state.error}</Text>
          </Box>
        )}
      </Flex>
    </Box>
  );
};

export default CveCweUpload;
