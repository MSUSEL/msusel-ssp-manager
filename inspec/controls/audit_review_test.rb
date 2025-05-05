control 'audit-review' do
  impact 1.0
  title 'Validate Audit Review, Analysis, and Reporting Controls'
  desc 'Ensure that the system reviews, analyzes, and reports audit records appropriately (AU-6)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify audit review configuration
  describe 'Audit review configuration' do
    # Get review configuration information
    review_config_response = http("#{app_url}/audit_review_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer admin_user_token'
                              })

    review_config = JSON.parse(review_config_response.body)

    it 'should have review enabled' do
      unless review_config['review_enabled'] == true
        fail "Audit review is not enabled"
      end
    end

    it 'should have appropriate review frequency' do
      unless review_config['review_frequency_hours'] <= 24
        fail "Review frequency too long: #{review_config['review_frequency_hours']} hours (should be <= 24)"
      end
    end

    it 'should have reviewers configured' do
      unless review_config['reviewers'] && review_config['reviewers'].length > 0
        fail "No reviewers configured for audit review"
      end
    end

    it 'should have automated review enabled' do
      unless review_config['automated_review_enabled'] == true
        fail "Automated audit review is not enabled"
      end
    end

    it 'should have automated tools configured' do
      unless review_config['automated_tools'] && review_config['automated_tools'].length > 0
        fail "No automated tools configured for audit review"
      end
    end
  end

  # Test case 2: Verify audit analysis configuration
  describe 'Audit analysis configuration' do
    # Get analysis configuration information
    analysis_config_response = http("#{app_url}/audit_analysis_config",
                                method: 'GET',
                                headers: {
                                  'Content-Type' => 'application/json',
                                  'Authorization' => 'Bearer admin_user_token'
                                })

    analysis_config = JSON.parse(analysis_config_response.body)

    it 'should have analysis enabled' do
      unless analysis_config['analysis_enabled'] == true
        fail "Audit analysis is not enabled"
      end
    end

    it 'should have analysis methods configured' do
      unless analysis_config['analysis_methods'] && analysis_config['analysis_methods'].length > 0
        fail "No analysis methods configured for audit analysis"
      end
    end

    it 'should have correlation enabled' do
      unless analysis_config['correlation_enabled'] == true
        fail "Audit correlation is not enabled"
      end
    end

    it 'should have correlation methods configured' do
      unless analysis_config['correlation_methods'] && analysis_config['correlation_methods'].length > 0
        fail "No correlation methods configured for audit analysis"
      end
    end
  end

  # Test case 3: Verify audit reporting configuration
  describe 'Audit reporting configuration' do
    # Get reporting configuration information
    reporting_config_response = http("#{app_url}/audit_reporting_config",
                                  method: 'GET',
                                  headers: {
                                    'Content-Type' => 'application/json',
                                    'Authorization' => 'Bearer admin_user_token'
                                  })

    reporting_config = JSON.parse(reporting_config_response.body)

    it 'should have reporting enabled' do
      unless reporting_config['reporting_enabled'] == true
        fail "Audit reporting is not enabled"
      end
    end

    it 'should have appropriate reporting frequency' do
      unless reporting_config['reporting_frequency_hours'] <= 168
        fail "Reporting frequency too long: #{reporting_config['reporting_frequency_hours']} hours (should be <= 168)"
      end
    end

    it 'should have report recipients configured' do
      unless reporting_config['report_recipients'] && reporting_config['report_recipients'].length > 0
        fail "No recipients configured for audit reporting"
      end
    end
  end

  # Test case 4: Verify risk-based adjustment configuration
  describe 'Risk-based adjustment configuration' do
    # Get risk adjustment configuration information
    risk_config_response = http("#{app_url}/audit_risk_config",
                              method: 'GET',
                              headers: {
                                'Content-Type' => 'application/json',
                                'Authorization' => 'Bearer admin_user_token'
                              })

    risk_config = JSON.parse(risk_config_response.body)

    it 'should have risk-based adjustment enabled' do
      unless risk_config['risk_adjustment_enabled'] == true
        fail "Risk-based adjustment is not enabled"
      end
    end

    it 'should have risk levels configured' do
      unless risk_config['risk_levels'] && risk_config['risk_levels'].length > 0
        fail "No risk levels configured for risk-based adjustment"
      end
    end
  end

  # Test case 5: Verify OPA policy validation
  describe 'OPA policy validation for audit review' do
    # Check OPA logs for audit review validation
    opa_log_content = file(log_file_path).content

    it 'should contain audit review validation in OPA logs' do
      keywords = %w[audit_review_configured audit_analysis_configured correlation_configured audit_reporting_configured risk_adjustment_configured findings_reported]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain audit review validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end

  # Test case 6: Verify audit findings reporting
  describe 'Audit findings reporting' do
    # Get findings information
    findings_response = http("#{app_url}/audit_findings",
                            method: 'GET',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer admin_user_token'
                            })

    findings = JSON.parse(findings_response.body)

    it 'should have findings available' do
      unless findings['findings'] && findings['findings'].length > 0
        fail "No audit findings available"
      end
    end

    it 'should include required information in findings' do
      if findings['findings'] && findings['findings'].length > 0
        finding = findings['findings'][0]
        missing_fields = []

        missing_fields << 'timestamp' unless finding['timestamp']
        missing_fields << 'severity' unless finding['severity']
        missing_fields << 'description' unless finding['description']
        missing_fields << 'affected_resources' unless finding['affected_resources']

        unless missing_fields.empty?
          fail "Findings missing required fields: #{missing_fields.join(', ')}"
        end
      end
    end
  end

  # Test case 7: Verify audit review process
  describe 'Audit review process' do
    # Simulate audit review
    simulate_response = http("#{app_url}/simulate_audit_review",
                            method: 'POST',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer admin_user_token'
                            },
                            data: { review_type: 'scheduled' }.to_json)

    simulate_result = JSON.parse(simulate_response.body)

    it 'should complete the review process' do
      unless simulate_result['review_completed'] == true
        fail "Audit review process did not complete"
      end
    end

    it 'should analyze audit records' do
      unless simulate_result['records_analyzed'] > 0
        fail "No audit records were analyzed"
      end
    end

    it 'should identify findings if applicable' do
      unless simulate_result['findings_identified'] != nil
        fail "Findings identification status not reported"
      end
    end

    it 'should report findings to recipients' do
      if simulate_result['findings_identified'] == true
        unless simulate_result['findings_reported'] == true
          fail "Findings were identified but not reported"
        end
      end
    end
  end

  # Test case 8: Verify integration with risk assessment
  describe 'Integration with risk assessment' do
    # Simulate risk level change
    risk_response = http("#{app_url}/simulate_risk_change",
                        method: 'POST',
                        headers: {
                          'Content-Type' => 'application/json',
                          'Authorization' => 'Bearer admin_user_token'
                        },
                        data: { risk_level: 'high' }.to_json)

    risk_result = JSON.parse(risk_response.body)

    it 'should adjust review frequency based on risk' do
      unless risk_result['review_frequency_adjusted'] == true
        fail "Review frequency not adjusted based on risk"
      end
    end

    it 'should adjust analysis methods based on risk' do
      unless risk_result['analysis_methods_adjusted'] == true
        fail "Analysis methods not adjusted based on risk"
      end
    end

    it 'should adjust reporting frequency based on risk' do
      unless risk_result['reporting_frequency_adjusted'] == true
        fail "Reporting frequency not adjusted based on risk"
      end
    end
  end
end
