import React from 'react';
import './IssueDetails.css';

interface VulnerabilityData {
  function: string;
  line_number: number[];
  issue_text: string[];
  issue_severity: string[];
  issue_confidence: string[];
  issue_cwe: { id: number; link: string }[];
  more_info: string[];
  filename: string;
}

const IssueDetails: React.FC<{ data: VulnerabilityData[] }> = ({ data }) => {
  // Group vulnerabilities by filename for better organization
  const groupedByFile = data.reduce((acc, vulnerability) => {
    const filename = vulnerability.filename;
    if (!acc[filename]) {
      acc[filename] = [];
    }
    acc[filename].push(vulnerability);
    return acc;
  }, {} as Record<string, VulnerabilityData[]>);
  return (
    <div className="issue-details-container">
      <h2>Security Issues Found</h2>
      <p className="description">
        The following security issues were detected in your codebase.
        Issues are grouped by file, with each card representing a vulnerable function and its associated issues.
        Found {data.length} vulnerable functions across {Object.keys(groupedByFile).length} files.
      </p>

      {Object.entries(groupedByFile).map(([filename, vulnerabilities]) => (
        <div key={filename} className="file-section">
          <h3 className="file-header">
            <span className="file-icon">📁</span>
            {filename.split('/').pop()} {/* Show just the filename */}
            <span className="file-path">{filename}</span>
          </h3>

          {vulnerabilities.map((vulnerability, vulnIndex) => (
            <div key={`${filename}-${vulnIndex}`} className="vulnerability-card">
              <div className="card-header">
                <h4>Function: <span className="highlight">{vulnerability.function}</span></h4>
              </div>

              <div className="issues-container">
                {vulnerability.line_number.map((lineNum, index) => (
                  <div
                    key={index}
                    className={`issue-item severity-${vulnerability.issue_severity[index].toLowerCase()}`}
                  >
                    <div className="issue-header">
                      <span className="line-number">Line {lineNum}</span>
                      <div className="issue-metrics">
                        <span className={`severity ${vulnerability.issue_severity[index].toLowerCase()}`}>
                          {vulnerability.issue_severity[index]}
                        </span>
                        <span className={`confidence ${vulnerability.issue_confidence[index].toLowerCase()}`}>
                          Confidence: {vulnerability.issue_confidence[index]}
                        </span>
                      </div>
                    </div>

                    <div className="issue-content">
                      <p className="issue-text">{vulnerability.issue_text[index]}</p>

                      <div className="issue-links">
                        <a
                          href={vulnerability.issue_cwe[index].link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="cwe-link"
                        >
                          CWE-{vulnerability.issue_cwe[index].id}
                        </a>
                        <a
                          href={vulnerability.more_info[index]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="more-info-link"
                        >
                          Learn More
                        </a>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
};

export default IssueDetails;
