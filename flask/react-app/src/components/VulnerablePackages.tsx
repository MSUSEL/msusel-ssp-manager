import React, { useState, useEffect } from 'react';
import './VulnerablePackages.css';

// TypeScript interfaces based on the package audit report structure

interface Vulnerability {
  id: string;
  description: string;
  fix_versions: string[];
  severity: string;
}

interface Package {
  name: string;
  installed_version: string;
  requested_version: string;
  installation_status: string;
  audit_status: string;
  vulnerability_count: number;
  vulnerabilities: Vulnerability[];
}

interface ReportMetadata {
  generated_at: string;
  report_type: string;
  total_packages: number;
}

interface Summary {
  packages_with_vulnerabilities: number;
  total_vulnerabilities: number;
  packages_clean: number;
  packages_failed_audit: number;
}

interface PackageAuditReport {
  report_metadata: ReportMetadata;
  summary: Summary;
  packages: Package[];
}

// Error response interface for when the backend returns an error
interface ErrorResponse {
  error: string;
  message: string;
}

// Union type for the API response
type ApiResponse = PackageAuditReport | ErrorResponse;

const VulnerablePackages: React.FC = () => {
  const [auditData, setAuditData] = useState<PackageAuditReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedPackages, setExpandedPackages] = useState<Set<string>>(new Set());

  // Helper function to check if response is an error
  const isErrorResponse = (data: ApiResponse): data is ErrorResponse => {
    return 'error' in data;
  };

  // Helper function to toggle package expansion
  const togglePackageExpansion = (packageName: string) => {
    const newExpanded = new Set(expandedPackages);
    if (newExpanded.has(packageName)) {
      newExpanded.delete(packageName);
    } else {
      newExpanded.add(packageName);
    }
    setExpandedPackages(newExpanded);
  };

  // Helper function to group packages by status
  const groupPackagesByStatus = (packages: Package[]) => {
    const vulnerable = packages.filter(pkg => pkg.vulnerability_count > 0);
    const clean = packages.filter(pkg => pkg.vulnerability_count === 0 && pkg.audit_status === 'success');
    const failed = packages.filter(pkg => pkg.audit_status !== 'success');

    return { vulnerable, clean, failed };
  };

  useEffect(() => {
    // Fetch package audit data from backend
    fetch('/api/vulnerable-packages/package_report')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((data: ApiResponse) => {
        if (isErrorResponse(data)) {
          setError(`${data.error}: ${data.message}`);
        } else {
          setAuditData(data);
        }
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching package audit data:', error);
        setError(`Failed to fetch package audit data: ${error.message}`);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="vulnerable-packages-container">
        <div className="loading-message">
          <h2>Loading Package Audit Report...</h2>
          <p>Please wait while we load the vulnerability data.</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="vulnerable-packages-container">
        <div className="error-message">
          <h2>Error Loading Package Audit Report</h2>
          <p>{error}</p>
          <button onClick={() => window.location.reload()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!auditData) {
    return (
      <div className="vulnerable-packages-container">
        <div className="no-data-message">
          <h2>No Package Audit Data Available</h2>
          <p>No package audit report data was found.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="vulnerable-packages-container">
      <h1>Package Vulnerability Audit Report</h1>
      <p className="description">
        This report shows security vulnerabilities found in your project's package dependencies.
        Generated on {new Date(auditData.report_metadata.generated_at).toLocaleString()}.
      </p>
      
      {/* Summary section with cards */}
      <div className="summary-section">
        <h2>Audit Summary</h2>
        <div className="summary-cards">
          <div className="summary-card total-packages">
            <div className="card-icon"></div>
            <div className="card-content">
              <h3>{auditData.report_metadata.total_packages}</h3>
              <p>Total Packages</p>
            </div>
          </div>

          <div className="summary-card vulnerable-packages">
            <div className="card-icon"></div>
            <div className="card-content">
              <h3>{auditData.summary.packages_with_vulnerabilities}</h3>
              <p>Vulnerable Packages</p>
            </div>
          </div>

          <div className="summary-card total-vulnerabilities">
            <div className="card-icon"></div>
            <div className="card-content">
              <h3>{auditData.summary.total_vulnerabilities}</h3>
              <p>Total Vulnerabilities</p>
            </div>
          </div>

          <div className="summary-card clean-packages">
            <div className="card-icon"></div>
            <div className="card-content">
              <h3>{auditData.summary.packages_clean}</h3>
              <p>Clean Packages</p>
            </div>
          </div>

          {auditData.summary.packages_failed_audit > 0 && (
            <div className="summary-card failed-audit">
              <div className="card-icon"></div>
              <div className="card-content">
                <h3>{auditData.summary.packages_failed_audit}</h3>
                <p>Failed Audits</p>
              </div>
            </div>
          )}
        </div>

        <div className="report-metadata">
          <p><strong>Report Generated:</strong> {new Date(auditData.report_metadata.generated_at).toLocaleString()}</p>
          <p><strong>Report Type:</strong> {auditData.report_metadata.report_type.replace(/_/g, ' ').toUpperCase()}</p>
        </div>
      </div>

      {/* Package list section */}
      <div className="packages-section">
        <h2>Package Details</h2>

        {(() => {
          const { vulnerable, clean, failed } = groupPackagesByStatus(auditData.packages);

          return (
            <>
              {/* Vulnerable packages */}
              {vulnerable.length > 0 && (
                <div className="package-group vulnerable-group">
                  <h3>Packages with Vulnerabilities ({vulnerable.length})</h3>
                  <div className="package-list">
                    {vulnerable.map((pkg) => (
                      <div key={pkg.name} className="package-item vulnerable">
                        <div
                          className="package-header"
                          onClick={() => togglePackageExpansion(pkg.name)}
                        >
                          <div className="package-info">
                            <h4>{pkg.name}</h4>
                            <span className="package-version">v{pkg.installed_version}</span>
                            <span className="vulnerability-count">
                              {pkg.vulnerability_count} vulnerabilities
                            </span>
                          </div>
                          <div className="expand-icon">
                            {expandedPackages.has(pkg.name) ? '▼' : '▶'}
                          </div>
                        </div>

                        {expandedPackages.has(pkg.name) && (
                          <div className="package-details">
                            <div className="package-metadata">
                              <p><strong>Requested Version:</strong> {pkg.requested_version}</p>
                              <p><strong>Installation Status:</strong> {pkg.installation_status}</p>
                              <p><strong>Audit Status:</strong> {pkg.audit_status}</p>
                            </div>
                            <div className="vulnerabilities-list">
                              <h5>Vulnerabilities ({pkg.vulnerability_count})</h5>
                              {pkg.vulnerabilities.map((vuln, index) => (
                                <div key={`${pkg.name}-${vuln.id}-${index}`} className="vulnerability-item">
                                  <div className="vulnerability-header">
                                    <div className="cve-id">
                                      <strong>{vuln.id}</strong>
                                    </div>
                                    <div className="severity-badge">
                                      <span className={`severity ${vuln.severity.toLowerCase()}`}>
                                        {vuln.severity.toUpperCase()}
                                      </span>
                                    </div>
                                  </div>

                                  <div className="vulnerability-description">
                                    <p>{vuln.description}</p>
                                  </div>

                                  {vuln.fix_versions.length > 0 && (
                                    <div className="fix-versions">
                                      <strong>Fix Available:</strong>
                                      <div className="version-tags">
                                        {vuln.fix_versions.map((version, vIndex) => (
                                          <span key={vIndex} className="version-tag">
                                            v{version}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {vuln.fix_versions.length === 0 && (
                                    <div className="no-fix">
                                      <span className="no-fix-badge">No fix available</span>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Clean packages */}
              {clean.length > 0 && (
                <div className="package-group clean-group">
                  <h3>Clean Packages ({clean.length})</h3>
                  <div className="package-list">
                    {clean.map((pkg) => (
                      <div key={pkg.name} className="package-item clean">
                        <div className="package-info">
                          <h4>{pkg.name}</h4>
                          <span className="package-version">v{pkg.installed_version}</span>
                          <span className="status-badge clean">No vulnerabilities</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Failed audit packages */}
              {failed.length > 0 && (
                <div className="package-group failed-group">
                  <h3>Failed Audits ({failed.length})</h3>
                  <div className="package-list">
                    {failed.map((pkg) => (
                      <div key={pkg.name} className="package-item failed">
                        <div className="package-info">
                          <h4>{pkg.name}</h4>
                          <span className="package-version">v{pkg.installed_version}</span>
                          <span className="status-badge failed">Audit failed</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          );
        })()}
      </div>
    </div>
  );
};

export default VulnerablePackages;
