control 'malicious-code-protection-policy' do
  impact 1.0
  title 'Validate Malicious Code Protection'
  desc 'Ensure that malicious code protection mechanisms are properly implemented (SI-3)'

  app_url = 'http://localhost:8000'
  log_file_path = '../logs/opa_interactions.log'

  # Test case 1: Safe file upload
  describe 'Safe file upload' do
    # Try to upload a safe file
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'document.txt',
                        content: 'This is a safe document with normal content.',
                        size: 100,
                        type: 'document'
                      }
                    }.to_json)

    it 'should allow safe file' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['allowed']).to eq(true)
      expect(JSON.parse(response.body)['malicious']).to eq(false)
    end
  end

  # Test case 2: Malicious file extension
  describe 'Malicious file extension' do
    # Try to upload a file with malicious extension
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'suspicious.exe',
                        content: 'Binary content',
                        size: 500,
                        type: 'executable',
                        approved: false
                      }
                    }.to_json)

    it 'should detect malicious file extension' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['allowed']).to eq(false)
      expect(JSON.parse(response.body)['malicious']).to eq(true)
      expect(JSON.parse(response.body)['reason']).to include('malicious extension')
    end
  end

  # Test case 3: Malicious content pattern
  describe 'Malicious content pattern' do
    # Try to upload a file with malicious content
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'script.txt',
                        content: 'This file contains <script>alert("malicious")</script> code',
                        size: 200,
                        type: 'document'
                      }
                    }.to_json)

    it 'should detect malicious content pattern' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['malicious']).to eq(true)
      expect(JSON.parse(response.body)['reason']).to include('malicious pattern')
    end
  end

  # Test case 4: Suspicious file size
  describe 'Suspicious file size' do
    # Try to upload a file with suspicious size
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'large_document.pdf',
                        content: 'Large content...',
                        size: 15000000, # 15MB
                        type: 'document'
                      }
                    }.to_json)

    it 'should detect suspicious file size' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['malicious']).to eq(true)
      expect(JSON.parse(response.body)['reason']).to include('suspicious size')
    end
  end

  # Test case 5: Approved executable
  describe 'Approved executable' do
    # Try to upload an approved executable
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'approved.exe',
                        content: 'Binary content',
                        size: 500,
                        type: 'executable',
                        approved: true
                      }
                    }.to_json)

    it 'should allow approved executable' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['allowed']).to eq(true)
      expect(JSON.parse(response.body)['malicious']).to eq(false)
    end
  end

  # Test case 6: Override for quarantine
  describe 'Override for quarantine' do
    # Try to upload a malicious file with override
    response = http("#{app_url}/scan_file",
                    method: 'POST',
                    headers: { 'Content-Type' => 'application/json' },
                    data: {
                      file: {
                        name: 'suspicious.exe',
                        content: 'Binary content',
                        size: 500,
                        type: 'executable',
                        approved: false,
                        override: true
                      }
                    }.to_json)

    it 'should quarantine file with override' do
      expect(response.status).to eq(200)
      expect(JSON.parse(response.body)['allowed']).to eq(false)
      expect(JSON.parse(response.body)['malicious']).to eq(true)
      expect(JSON.parse(response.body)['action']).to eq('quarantine')
    end
  end

  # Validate OPA logs for malicious code protection decisions
  describe file(log_file_path) do
    its('content') { should include 'malicious_code_protection' }
    its('content') { should include 'malicious_code_detected' }
  end
end
