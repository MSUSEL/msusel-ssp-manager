import React from 'react';
import './IssueDetails.css';

interface IssueData {
  function: string;
  line_number: number[];
  issue_text: string[];
  issue_severity: string[];
  issue_confidence: string[];
  issue_cwe: { id: number; link: string }[];
  more_info: string[];
  filename: string;
}

const IssueDetails: React.FC<{ data: IssueData }> = ({ data }) => {
  return (
    <div className="issue-details-container">
      <h2>Security Issues Found</h2>
      <p className="description">
        The following security issues were detected in your codebase. 
        Each card represents a vulnerable function and its associated issues.
      </p>

      <div className="vulnerability-card">
        <div className="card-header">
          <h3>Function: <span className="highlight">{data.function}</span></h3>
          <div className="file-info">
            <span className="label">File:</span>
            <span className="value">{data.filename}</span>
          </div>
        </div>

        <div className="issues-container">
          {data.line_number.map((lineNum, index) => (
            <div 
              key={index} 
              className={`issue-item severity-${data.issue_severity[index].toLowerCase()}`}
            >
              <div className="issue-header">
                <span className="line-number">Line {lineNum}</span>
                <div className="issue-metrics">
                  <span className={`severity ${data.issue_severity[index].toLowerCase()}`}>
                    {data.issue_severity[index]}
                  </span>
                  <span className={`confidence ${data.issue_confidence[index].toLowerCase()}`}>
                    Confidence: {data.issue_confidence[index]}
                  </span>
                </div>
              </div>

              <div className="issue-content">
                <p className="issue-text">{data.issue_text[index]}</p>
                
                <div className="issue-links">
                  <a 
                    href={data.issue_cwe[index].link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="cwe-link"
                  >
                    CWE-{data.issue_cwe[index].id}
                  </a>
                  <a 
                    href={data.more_info[index]}
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
    </div>
  );
};

export default IssueDetails;
