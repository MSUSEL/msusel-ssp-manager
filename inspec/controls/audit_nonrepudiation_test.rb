control 'audit-nonrepudiation' do
  impact 1.0
  title 'Validate Non-repudiation Controls'
  desc 'Ensure that the system protects against an individual falsely denying having performed a particular action and provides evidence of individual actions (AU-10)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'
  audit_log_path = './logs/audit.log'

  # Test case 1: Verify digital signature configuration
  describe 'Digital signature configuration' do
    # Get digital signature configuration information
    digital_signature_response = http("#{app_url}/digital_signature_config",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                    })

    digital_signature = JSON.parse(digital_signature_response.body)

    it 'should have digital signatures enabled' do
      unless digital_signature['enabled'] == true
        fail "Digital signatures are not enabled"
      end
    end

    it 'should use strong signature algorithm' do
      strong_algorithms = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384', 'ECDSA-P521', 'Ed25519']
      unless strong_algorithms.include?(digital_signature['algorithm'])
        fail "Weak signature algorithm: #{digital_signature['algorithm']}"
      end
    end

    it 'should have key management enabled' do
      unless digital_signature['key_management'] && digital_signature['key_management']['enabled'] == true
        fail "Key management is not enabled for digital signatures"
      end
    end

    it 'should have appropriate key protection' do
      unless digital_signature['key_management']['protection_mechanism'] && 
             ['hardware_security_module', 'secure_enclave', 'trusted_platform_module'].include?(digital_signature['key_management']['protection_mechanism'])
        fail "Inadequate key protection mechanism: #{digital_signature['key_management']['protection_mechanism']}"
      end
    end
  end

  # Test case 2: Verify identity binding configuration
  describe 'Identity binding configuration' do
    # Get identity binding configuration information
    identity_binding_response = http("#{app_url}/identity_binding_config",
                                  method: 'GET',
                                  headers: {
                                    'Content-Type' => 'application/json',
                                    'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                  })

    identity_binding = JSON.parse(identity_binding_response.body)

    it 'should have identity binding enabled' do
      unless identity_binding['enabled'] == true
        fail "Identity binding is not enabled"
      end
    end

    it 'should have binding mechanisms configured' do
      unless identity_binding['mechanisms'] && identity_binding['mechanisms'].length > 0
        fail "No identity binding mechanisms configured"
      end
    end

    it 'should require identity verification' do
      unless identity_binding['identity_verification_required'] == true
        fail "Identity verification is not required"
      end
    end

    it 'should use strong authentication for identity binding' do
      has_strong_auth = identity_binding['mechanisms'].any? { |m| 
        ['multi_factor', 'certificate_based', 'biometric'].include?(m['type'])
      }
      unless has_strong_auth
        fail "No strong authentication mechanism for identity binding"
      end
    end
  end

  # Test case 3: Verify signature validation configuration
  describe 'Signature validation configuration' do
    # Get signature validation configuration information
    signature_validation_response = http("#{app_url}/signature_validation_config",
                                      method: 'GET',
                                      headers: {
                                        'Content-Type' => 'application/json',
                                        'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                      })

    signature_validation = JSON.parse(signature_validation_response.body)

    it 'should have signature validation enabled' do
      unless signature_validation['enabled'] == true
        fail "Signature validation is not enabled"
      end
    end

    it 'should have validation mechanisms configured' do
      unless signature_validation['mechanisms'] && signature_validation['mechanisms'].length > 0
        fail "No signature validation mechanisms configured"
      end
    end

    it 'should enforce validation' do
      unless signature_validation['enforce_validation'] == true
        fail "Signature validation is not enforced"
      end
    end

    it 'should check certificate revocation' do
      has_revocation_check = signature_validation['mechanisms'].any? { |m| 
        m['type'] == 'certificate_validation' && m['check_revocation'] == true
      }
      unless has_revocation_check
        fail "Certificate revocation checking is not enabled"
      end
    end
  end

  # Test case 4: Verify timestamp binding configuration
  describe 'Timestamp binding configuration' do
    # Get timestamp binding configuration information
    timestamp_binding_response = http("#{app_url}/timestamp_binding_config",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                    })

    timestamp_binding = JSON.parse(timestamp_binding_response.body)

    it 'should have timestamp binding enabled' do
      unless timestamp_binding['enabled'] == true
        fail "Timestamp binding is not enabled"
      end
    end

    it 'should use trusted timestamp source' do
      unless timestamp_binding['trusted_timestamp_source'] == true
        fail "Timestamp source is not trusted"
      end
    end

    it 'should use cryptographic binding' do
      unless timestamp_binding['cryptographic_binding'] == true
        fail "Cryptographic binding for timestamps is not enabled"
      end
    end

    it 'should have timestamp source verification' do
      unless timestamp_binding['source_verification_enabled'] == true
        fail "Timestamp source verification is not enabled"
      end
    end
  end

  # Test case 5: Verify evidence collection configuration
  describe 'Evidence collection configuration' do
    # Get evidence collection configuration information
    evidence_collection_response = http("#{app_url}/evidence_collection_config",
                                      method: 'GET',
                                      headers: {
                                        'Content-Type' => 'application/json',
                                        'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                      })

    evidence_collection = JSON.parse(evidence_collection_response.body)

    it 'should have evidence collection enabled' do
      unless evidence_collection['enabled'] == true
        fail "Evidence collection is not enabled"
      end
    end

    it 'should have collection mechanisms configured' do
      unless evidence_collection['mechanisms'] && evidence_collection['mechanisms'].length > 0
        fail "No evidence collection mechanisms configured"
      end
    end

    it 'should have secure storage for evidence' do
      unless evidence_collection['secure_storage'] == true
        fail "Secure storage for evidence is not enabled"
      end
    end

    it 'should collect comprehensive evidence' do
      required_evidence_types = ['user_actions', 'system_events', 'authentication_events', 'authorization_decisions']
      collected_types = evidence_collection['mechanisms'].map { |m| m['evidence_type'] }
      
      missing_types = required_evidence_types - collected_types
      unless missing_types.empty?
        fail "Missing evidence collection for types: #{missing_types.join(', ')}"
      end
    end
  end

  # Test case 6: Verify chain of custody configuration
  describe 'Chain of custody configuration' do
    # Get chain of custody configuration information
    chain_of_custody_response = http("#{app_url}/chain_of_custody_config",
                                    method: 'GET',
                                    headers: {
                                      'Content-Type' => 'application/json',
                                      'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                                    })

    chain_of_custody = JSON.parse(chain_of_custody_response.body)

    it 'should have chain of custody enabled' do
      unless chain_of_custody['enabled'] == true
        fail "Chain of custody is not enabled"
      end
    end

    it 'should have tracking mechanisms configured' do
      unless chain_of_custody['tracking_mechanisms'] && chain_of_custody['tracking_mechanisms'].length > 0
        fail "No chain of custody tracking mechanisms configured"
      end
    end

    it 'should have custody verification enabled' do
      unless chain_of_custody['verification_enabled'] == true
        fail "Chain of custody verification is not enabled"
      end
    end

    it 'should use tamper-evident mechanisms' do
      has_tamper_evident = chain_of_custody['tracking_mechanisms'].any? { |m| m['tamper_evident'] == true }
      unless has_tamper_evident
        fail "No tamper-evident mechanisms for chain of custody"
      end
    end
  end

  # Test case 7: Verify signature validation endpoint
  describe 'Signature validation endpoint' do
    # Test valid signature
    valid_signature_data = {
      signature: {
        value: "MIGIAkIB6Jkz6f4hL6rjh0UptQwVuQG9KaWF2Tz/c+B9ULxR4mIEtxbn1hXJOAIm1WvMK2mcOIuqTwjQQODZ9CWRISsCQgCL9MRmF5x/YPRvJHMhRVFLZSZn0MkVVn6i3mIbRXLjXj+PQRIQQvhTYrXL+5CZnSU0WjNqRWb7h5FQgwwYCGCCsGAQUF",
        issuer: "trusted_authority",
        expiration: (Time.now + 3600).utc.iso8601 # 1 hour from now
      }
    }
    
    validate_response = http("#{app_url}/validate_signature",
                            method: 'POST',
                            headers: {
                              'Content-Type' => 'application/json',
                              'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                            },
                            data: valid_signature_data.to_json)

    validation_result = JSON.parse(validate_response.body)

    it 'should validate correct signatures' do
      unless validation_result['valid'] == true
        fail "Valid signature not recognized"
      end
    end

    # Test invalid signature
    invalid_signature_data = {
      signature: {
        value: "INVALID_SIGNATURE_VALUE",
        issuer: "untrusted_source",
        expiration: (Time.now + 3600).utc.iso8601 # 1 hour from now
      }
    }
    
    invalid_response = http("#{app_url}/validate_signature",
                          method: 'POST',
                          headers: {
                            'Content-Type' => 'application/json',
                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                          },
                          data: invalid_signature_data.to_json)

    invalid_result = JSON.parse(invalid_response.body)

    it 'should reject incorrect signatures' do
      unless invalid_result['valid'] == false
        fail "Invalid signature not rejected"
      end
    end
  end

  # Test case 8: Verify action non-repudiation
  describe 'Action non-repudiation' do
    # Create a test action with non-repudiation
    action_data = {
      action: {
        type: "document_approval",
        resource: "contract_123",
        user: "test_user",
        timestamp: Time.now.utc.iso8601
      }
    }
    
    action_response = http("#{app_url}/create_action_with_nonrepudiation",
                          method: 'POST',
                          headers: {
                            'Content-Type' => 'application/json',
                            'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbl91c2VyIiwicm9sZXMiOlsidXNlciIsImFkbWluIl0sImlhdCI6MTUxNjIzOTAyMn0.xYOImKIq9kK3yXAylVtCec6fQoLJwBQwwDVhvpYONKo'
                          },
                          data: action_data.to_json)

    action_result = JSON.parse(action_response.body)

    it 'should create actions with digital signatures' do
      unless action_result['signature'] && !action_result['signature'].empty?
        fail "Action does not have a digital signature"
      end
    end

    it 'should create actions with identity binding' do
      unless action_result['identity'] && !action_result['identity'].empty?
        fail "Action does not have identity binding"
      end
    end

    it 'should create actions with secure timestamps' do
      unless action_result['secure_timestamp'] && !action_result['secure_timestamp'].empty?
        fail "Action does not have a secure timestamp"
      end
    end

    it 'should log actions for evidence' do
      unless action_result['logged'] == true
        fail "Action was not logged for evidence"
      end
    end
  end

  # Test case 9: Verify OPA policy validation
  describe 'OPA policy validation for non-repudiation' do
    # Check OPA logs for non-repudiation validation
    opa_log_content = file(log_file_path).content

    it 'should contain non-repudiation validation in OPA logs' do
      keywords = %w[digital_signature_configured identity_binding_configured signature_validation_configured 
                    timestamp_binding_configured evidence_collection_configured chain_of_custody_configured]
      missing_keywords = keywords.reject { |keyword| opa_log_content.include?(keyword) }

      unless missing_keywords.empty?
        fail "OPA logs do not contain non-repudiation validation keywords: #{missing_keywords.join(', ')}"
      end
    end
  end
end
