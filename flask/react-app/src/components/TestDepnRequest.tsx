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

  // Project directory upload state
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [projectName, setProjectName] = useState<string>('');

  // Controls file upload state
  const [selectedControlsFile, setSelectedControlsFile] = useState<File | null>(null);

  // Common state
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<{current: number, total: number} | null>(null);
  const [vulnerabilityEffectivenessResults, setvulnerabilityEffectivenessResults] = useState<any | null>(null);
  const [moduleName, setModuleName] = useState<string>('');
  const [functionName, setFunctionName] = useState<string>('');

  // Refs for file inputs
  const directoryInputRef = useRef<HTMLInputElement>(null);
  const controlsFileInputRef = useRef<HTMLInputElement>(null);

  const handleDirectoryClick = () => {
    directoryInputRef.current?.click();
  };

  const handleControlsFileClick = () => {
    controlsFileInputRef.current?.click();
  };

  const handleDirectoryChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      // Validate directory structure and files
      const validationResult = validateDirectoryUpload(files);
      if (!validationResult.isValid) {
        setUploadStatus(`Invalid directory: ${validationResult.error}`);
        return;
      }

      setSelectedFiles(files);

      // Extract project name from the first file's path
      const firstFile = files[0];
      const pathParts = firstFile.webkitRelativePath.split('/');
      const extractedProjectName = pathParts[0] || 'Unknown Project';
      setProjectName(extractedProjectName);

      setUploadStatus(null); // Clear previous status
      setUploadProgress(null); // Clear previous progress
      setvulnerabilityEffectivenessResults(null); // Clear previous results
    }
  };

  const handleControlsFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files.length > 0) {
      setSelectedControlsFile(files[0]);
      setUploadStatus(null); // Clear previous status
      setUploadProgress(null); // Clear previous progress
      setvulnerabilityEffectivenessResults(null); // Clear previous results
    }
  };

  // Validate directory upload structure and requirements
  const validateDirectoryUpload = (files: FileList): {isValid: boolean, error?: string} => {
    if (files.length === 0) {
      return {isValid: false, error: 'No files selected'};
    }

    // Check for requirements.txt at root level
    let hasRequirements = false;
    const fileList = Array.from(files);

    for (const file of fileList) {
      const relativePath = file.webkitRelativePath;

      // Check if requirements.txt exists at root level (no subdirectories)
      if (relativePath === 'requirements.txt' || relativePath.endsWith('/requirements.txt')) {
        const pathParts = relativePath.split('/');
        if (pathParts.length === 2 && pathParts[1] === 'requirements.txt') {
          hasRequirements = true;
          break;
        }
      }
    }

    if (!hasRequirements) {
      return {isValid: false, error: 'requirements.txt not found at project root level'};
    }

    // Check for reasonable file count (prevent accidental large uploads)
    if (files.length > 1000) {
      return {isValid: false, error: `Too many files (${files.length}). Maximum 1000 files allowed.`};
    }

    return {isValid: true};
  };

  const handleUpload = async () => {
    // Basic validation - check fields aren't empty
    if (!moduleName.trim() || !functionName.trim()) {
      setUploadStatus('Module name and function name are required');
      return;
    }

    // Check if we have both project directory and controls file selected
    if (!selectedFiles || !selectedControlsFile) {
      setUploadStatus('Please select both a project directory and controls file');
      return;
    }

    setUploading(true);
    const formData = new FormData();

    // Add entry point parameters
    formData.append('module_name', moduleName.trim());
    formData.append('function_name', functionName.trim());

    // Add controls file
    formData.append('controls_file', selectedControlsFile);

    // Directory upload with enhanced file handling and path preservation
    const fileArray: File[] = Array.from(selectedFiles);

    // Validate files before upload
    const invalidFiles = fileArray.filter((file: File) => {
      const path = file.webkitRelativePath;
      return !path || path.includes('..') || path.startsWith('/');
    });

    if (invalidFiles.length > 0) {
      setUploadStatus(`Invalid files detected: ${invalidFiles.length} files have unsafe paths`);
      setUploading(false);
      return;
    }

    // Add files to FormData with preserved relative paths
    setUploadProgress({current: 0, total: fileArray.length});

    for (let i = 0; i < fileArray.length; i++) {
      const file: File = fileArray[i];
      formData.append('files', file);

      // Update progress for UI feedback
      setUploadProgress({current: i + 1, total: fileArray.length});
    }

    // Use the directory upload endpoint
    const endpoint = `${apiEndpoint}/directory`;

    // Log upload details for debugging
    console.log(`Uploading ${fileArray.length} files from project: ${projectName}`);
    console.log(`Controls file: ${selectedControlsFile.name}`);
    fileArray.slice(0, 5).forEach((file: File) => {
      console.log(`  - ${file.webkitRelativePath} (${file.size} bytes)`);
    });
    if (fileArray.length > 5) {
      console.log(`  ... and ${fileArray.length - 5} more files`);
    }

    try {
      setUploadStatus(`Downloading dependencies source code for analysis. This can take some time.`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10800000); // 3 hours timeout

      const response = await fetch(endpoint, {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const resultText = await response.json(); // Parse JSON response
        setvulnerabilityEffectivenessResults(resultText);

        setUploadStatus(`✅ Project "${projectName}" (${selectedFiles.length} files) and controls file successfully uploaded and analyzed`);
      } else {
        // Try to get error message from response
        try {
          const errorData = await response.json();
          setUploadStatus(`❌ Upload failed: ${errorData.error || 'Unknown error'}`);
        } catch {
          setUploadStatus(`❌ Project upload or analysis failed`);
        }
      }
    } catch (error) {
      setUploadStatus(`❌ Error uploading project: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setUploading(false);
      setUploadProgress(null); // Clear progress indicator
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

        <div className="entry-point-help">
          <div className="help-header">
            <h4>Entry Point Configuration</h4>
          </div>
          <div className="help-content">
            <p>Specify the entry point for dynamic analysis using Python import syntax:</p>
            <div className="help-examples">
              <div className="example-item">
                <span className="example-label">File in root:</span>
                <code>main</code> <span className="example-desc">→ main.py</span>
              </div>
              <div className="example-item">
                <span className="example-label">File in package:</span>
                <code>src.app</code> <span className="example-desc">→ src/app.py</span>
              </div>
              <div className="example-item">
                <span className="example-label">Nested package:</span>
                <code>utils.database.connection</code> <span className="example-desc">→ utils/database/connection.py</span>
              </div>
            </div>
            <div className="help-note">
              <span>Use dots (.) to separate directories, just like Python imports</span>
            </div>
          </div>
        </div>

        <div className="file-selection-container">
          <div className="upload-section">
            <h4>Project Directory</h4>
            <p>Upload your entire project directory (must contain requirements.txt at root level)</p>
            <button
              onClick={handleDirectoryClick}
              className="control-button directory-button"
            >
              <span>📁</span> Select Project Directory
            </button>
            <input
              type="file"
              ref={directoryInputRef}
              style={{ display: 'none' }}
              onChange={handleDirectoryChange}
              webkitdirectory=""
              directory=""
              multiple
            />

            {selectedFiles && (
              <div className="selected-file-info">
                <span className="file-icon">📁</span>
                <div className="directory-info">
                  <div className="project-name">{projectName}</div>
                  <div className="file-count">{selectedFiles.length} files selected</div>
                </div>
              </div>
            )}
          </div>

          <div className="upload-section">
            <h4>Controls File</h4>
            <p>Upload your controls JSON file for security analysis</p>
            <button
              onClick={handleControlsFileClick}
              className="control-button"
            >
              <span>📄</span> Select Controls File
            </button>
            <input
              type="file"
              ref={controlsFileInputRef}
              style={{ display: 'none' }}
              onChange={handleControlsFileChange}
              accept=".json"
            />

            {selectedControlsFile && (
              <div className="selected-file-info">
                <span className="file-icon">📄</span> {selectedControlsFile.name}
              </div>
            )}
          </div>

          <div className="entry-point-inputs">
            <div className="input-group">
              <label htmlFor="module-name">Module Name:</label>
              <input
                id="module-name"
                type="text"
                value={moduleName}
                onChange={(e) => setModuleName(e.target.value)}
                className="entry-point-input"
              />
            </div>
            <div className="input-group">
              <label htmlFor="function-name">Function Name:</label>
              <input
                id="function-name"
                type="text"
                value={functionName}
                onChange={(e) => setFunctionName(e.target.value)}
                className="entry-point-input"
              />
            </div>
          </div>

          {(selectedFiles && selectedControlsFile) && (
            <div className="upload-action">
              <button
                onClick={handleUpload}
                disabled={uploading}
                className={`upload-button ${uploading ? 'disabled' : ''}`}
              >
                {uploading ? 'Analyzing...' : 'Analyze Project'}
              </button>
            </div>
          )}
        </div>

        {uploadStatus && <div className="status-message">{uploadStatus}</div>}

        {uploadProgress && (
          <div className="upload-progress">
            <div className="progress-info">
              <span>Processing files: {uploadProgress.current} / {uploadProgress.total}</span>
              <span>{Math.round((uploadProgress.current / uploadProgress.total) * 100)}%</span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{width: `${(uploadProgress.current / uploadProgress.total) * 100}%`}}
              ></div>
            </div>
          </div>
        )}

        {vulnerabilityEffectivenessResults && (
          <div className="results-container">
            <h3>Vulnerability Analysis Results</h3>
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
