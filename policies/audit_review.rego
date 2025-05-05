package security.audit_review

import rego.v1

# AU-6: Audit Review, Analysis, and Reporting
# This policy validates that the system:
# a. Reviews and analyzes audit records for indications of inappropriate or unusual activity
# b. Reports findings to designated organizational officials
# c. Adjusts the level of audit review, analysis, and reporting based on risk assessment

# Check if audit review is properly configured
audit_review_configured if {
    # Verify that review is enabled
    input.audit_review.review_enabled == true
    
    # Verify that review frequency is appropriate
    input.audit_review.review_frequency_hours <= 24
    
    # Verify that reviewers are configured
    count(input.audit_review.reviewers) > 0
}

# Check if automated review tools are properly configured
automated_review_configured if {
    # Verify that automated review is enabled
    input.audit_review.automated_review_enabled == true
    
    # Verify that automated tools are configured
    count(input.audit_review.automated_tools) > 0
}

# Check if audit analysis is properly configured
audit_analysis_configured if {
    # Verify that analysis is enabled
    input.audit_review.analysis_enabled == true
    
    # Verify that analysis methods are configured
    count(input.audit_review.analysis_methods) > 0
}

# Check if correlation capabilities are properly configured
correlation_configured if {
    # Verify that correlation is enabled
    input.audit_review.correlation_enabled == true
    
    # Verify that correlation methods are configured
    count(input.audit_review.correlation_methods) > 0
}

# Check if audit reporting is properly configured
audit_reporting_configured if {
    # Verify that reporting is enabled
    input.audit_review.reporting_enabled == true
    
    # Verify that reporting frequency is appropriate
    input.audit_review.reporting_frequency_hours <= 168  # Weekly
    
    # Verify that report recipients are configured
    count(input.audit_review.report_recipients) > 0
}

# Check if risk-based adjustment is properly configured
risk_adjustment_configured if {
    # Verify that risk-based adjustment is enabled
    input.audit_review.risk_adjustment_enabled == true
    
    # Verify that risk levels are configured
    count(input.audit_review.risk_levels) > 0
}

# Check if findings are properly reported
findings_reported if {
    # Verify that findings are reported
    input.audit_review.findings_reported == true
    
    # Verify that findings include required information
    input.audit_review.findings.timestamp
    input.audit_review.findings.severity
    input.audit_review.findings.description
    input.audit_review.findings.affected_resources
}

# Final decision on audit review compliance
audit_review_compliant if {
    audit_review_configured
    automated_review_configured
    audit_analysis_configured
    correlation_configured
    audit_reporting_configured
    risk_adjustment_configured
}

# Generate detailed compliance report
compliance_report := {
    "audit_review_configured": audit_review_configured,
    "automated_review_configured": automated_review_configured,
    "audit_analysis_configured": audit_analysis_configured,
    "correlation_configured": correlation_configured,
    "audit_reporting_configured": audit_reporting_configured,
    "risk_adjustment_configured": risk_adjustment_configured,
    "findings_reported": findings_reported,
    "overall_compliant": audit_review_compliant
}
