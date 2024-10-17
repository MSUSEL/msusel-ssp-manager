import React from 'react';
import './IssueDetails.css'; // Add custom styles here if needed

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
    <div className="issue-details">
      <h2>Issue Details</h2>
      <table className="issue-table">
        <thead>
          <tr>
            <th>Function</th>
            <th>Filename</th>
            <th>Line Numbers</th>
            <th>Issue Text</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>CWE</th>
            <th>More Info</th>
          </tr>
        </thead>
        <tbody>
          {data.line_number.map((_, index) => (
            <tr key={index}>
              {index === 0 && (
                <>
                  <td rowSpan={data.line_number.length}>{data.function}</td>
                  <td rowSpan={data.line_number.length}>{data.filename}</td>
                </>
              )}
              <td>{data.line_number[index]}</td>
              <td>{data.issue_text[index]}</td>
              <td>{data.issue_severity[index]}</td>
              <td>{data.issue_confidence[index]}</td>
              <td>
                <a href={data.issue_cwe[index].link} target="_blank" rel="noopener noreferrer">
                  CWE-{data.issue_cwe[index].id}
                </a>
              </td>
              <td>
                <a href={data.more_info[index]} target="_blank" rel="noopener noreferrer">
                  More Info
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default IssueDetails;
