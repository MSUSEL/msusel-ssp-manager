control 'input-validation-policy' do
  impact 1.0
  title 'Validate Input Validation Controls'
  desc 'Ensure that input validation mechanisms are properly enforced (SI-3, SI-7)'

  app_url = 'http://localhost:8000'
  log_file_path = './logs/opa_interactions.log'

  # Test case 1: Valid input
  describe 'Valid input submission' do
    # Submit valid input
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'email',
                      data: 'test@example.com'
                    }.to_json)

    it 'should accept valid input' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['valid']).to eq(true)
    end
  end

  # Test case 2: SQL injection attempt
  describe 'SQL injection attempt' do
    # Submit input with SQL injection
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'text',
                      data: "' OR 1=1; --"
                    }.to_json)

    it 'should reject SQL injection attempt' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('SQL injection')
    end
  end

  # Test case 3: XSS attempt
  describe 'XSS attempt' do
    # Submit input with XSS
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'text',
                      data: "<script>alert('XSS')</script>"
                    }.to_json)

    it 'should reject XSS attempt' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('XSS')
    end
  end

  # Test case 4: Input length validation
  describe 'Input length validation' do
    # Submit input that exceeds maximum length
    long_input = 'a' * 1000
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'username',
                      data: long_input
                    }.to_json)

    it 'should reject input exceeding maximum length' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('length')
    end
  end

  # Test case 5: Email format validation
  describe 'Email format validation' do
    # Submit invalid email format
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'email',
                      data: 'not-an-email'
                    }.to_json)

    it 'should reject invalid email format' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('format')
    end
  end

  # Test case 6: Date format validation
  describe 'Date format validation' do
    # Submit invalid date format
    response = http("#{app_url}/submit_data",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      field_type: 'date',
                      data: '01/01/2023'  # Not in YYYY-MM-DD format
                    }.to_json)

    it 'should reject invalid date format' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('format')
    end
  end

  # Test case 7: File integrity validation
  describe 'File integrity validation' do
    # Submit file with valid hash
    response = http("#{app_url}/validate_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      file: {
                        name: 'config.json',
                        hash: 'a1b2c3d4e5f6g7h8i9j0'
                      }
                    }.to_json)

    it 'should validate file with correct hash' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['valid']).to eq(true)
    end
  end

  # Test case 8: File integrity validation with invalid hash
  describe 'File integrity validation with invalid hash' do
    # Submit file with invalid hash
    response = http("#{app_url}/validate_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: { 
                      file: {
                        name: 'config.json',
                        hash: 'invalid_hash'
                      }
                    }.to_json)

    it 'should reject file with incorrect hash' do
      expect(response.status).to eq(400)
      expect(JSON.parse(response.body)['valid']).to eq(false)
      expect(JSON.parse(response.body)['reason']).to include('integrity')
    end
  end

  # Validate OPA logs for input validation decisions
  describe file(log_file_path) do
    its('content') { should include 'input_validation' }
    its('content') { should include 'sql_injection_detected' }
    its('content') { should include 'xss_detected' }
    its('content') { should include 'input_length_valid' }
    its('content') { should include 'input_format_valid' }
    its('content') { should include 'file_integrity_valid' }
  end
end
