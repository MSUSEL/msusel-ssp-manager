const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const app = express();
const port = 8000;

// Middleware
app.use(bodyParser.json());

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Initialize log files
const opaLogPath = path.join(logsDir, 'opa_interactions.log');
const auditLogPath = path.join(logsDir, 'audit.log');

if (!fs.existsSync(opaLogPath)) {
  fs.writeFileSync(opaLogPath, '');
}

if (!fs.existsSync(auditLogPath)) {
  fs.writeFileSync(auditLogPath, '');
}

// Helper function to log OPA interactions
function logOpaInteraction(data) {
  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...data
  }) + '\n';
  fs.appendFileSync(opaLogPath, logEntry);
}

// Helper function to log audit events
function logAuditEvent(data) {
  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...data
  }) + '\n';
  fs.appendFileSync(auditLogPath, logEntry);
}

// Sample user data
const users = {
  'regular_user': {
    id: 'regular_user',
    password: 'SecurePassword123',
    roles: ['user'],
    type: 'regular',
    status: 'active'
  },
  'staff_user': {
    id: 'staff_user',
    password: 'StaffSecurePass789',
    roles: ['user', 'staff'],
    type: 'staff',
    status: 'active'
  },
  'admin_user': {
    id: 'admin_user',
    password: 'AdminSecurePass456',
    roles: ['user', 'admin'],
    type: 'admin',
    status: 'active'
  }
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password, mfa_code, type, factors } = req.body;
  const user = users[username];

  // Log the login attempt
  logAuditEvent({
    event_type: 'login',
    user_id: username,
    ip_address: req.ip,
    auth_method: factors >= 2 ? 'mfa' : 'password',
    outcome: user && user.password === password ? 'success' : 'failure'
  });

  // Check if user exists and password is correct
  if (!user || user.password !== password) {
    return res.status(401).json({
      authenticated: false,
      reason: 'Invalid username or password'
    });
  }

  // Check if MFA is required for staff and admin users
  if ((user.type === 'staff' || user.type === 'admin') && factors < 2) {
    return res.status(401).json({
      authenticated: false,
      reason: 'MFA required for staff and admin users'
    });
  }

  // Generate a token
  const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify({
    sub: username,
    role: user.roles.includes('admin') ? 'admin' : 'user',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    jti: Math.random().toString(36).substring(2)
  })).toString('base64')}.signature`;

  // Log OPA interaction
  logOpaInteraction({
    package: 'security.authentication',
    decision: 'authentication_valid',
    input: {
      user: {
        id: username,
        type: user.type
      },
      authentication: {
        method: factors >= 2 ? 'mfa' : 'password',
        factors: factors
      },
      token: {
        payload: {
          sub: username,
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      },
      now: Math.floor(Date.now() / 1000)
    },
    result: true
  });

  return res.status(200).json({
    authenticated: true,
    access_token: token
  });
});

// User profile endpoint
app.get('/user_profile', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      allowed: false,
      reason: 'No token provided'
    });
  }

  const token = authHeader.split(' ')[1];
  const tokenParts = token.split('.');
  
  if (tokenParts.length !== 3) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token format'
    });
  }

  try {
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
    const username = payload.sub;
    const user = users[username];

    if (!user) {
      return res.status(401).json({
        allowed: false,
        reason: 'User not found'
      });
    }

    // Log OPA interaction
    logOpaInteraction({
      package: 'security.access_control',
      decision: 'allow_access',
      input: {
        user: {
          id: username,
          roles: user.roles,
          status: user.status
        },
        resource: 'user_profile',
        action: 'access_resource',
        request: {
          time: new Date().toISOString(),
          ip: req.ip
        }
      },
      result: true
    });

    // Log audit event
    logAuditEvent({
      event_type: 'data_access',
      user_id: username,
      resource: 'user_profile',
      outcome: 'success',
      data_id: username
    });

    return res.status(200).json({
      allowed: true,
      profile: {
        username: username,
        roles: user.roles,
        type: user.type
      }
    });
  } catch (error) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token'
    });
  }
});

// Admin panel endpoint
app.get('/admin_panel', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      allowed: false,
      reason: 'No token provided'
    });
  }

  const token = authHeader.split(' ')[1];
  const tokenParts = token.split('.');
  
  if (tokenParts.length !== 3) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token format'
    });
  }

  try {
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
    const username = payload.sub;
    const user = users[username];

    if (!user) {
      return res.status(401).json({
        allowed: false,
        reason: 'User not found'
      });
    }

    // Check if user has admin role
    if (!user.roles.includes('admin')) {
      // Log OPA interaction
      logOpaInteraction({
        package: 'security.access_control',
        decision: 'deny_access',
        input: {
          user: {
            id: username,
            roles: user.roles,
            status: user.status
          },
          resource: 'admin_panel',
          action: 'access_resource',
          request: {
            time: new Date().toISOString(),
            ip: req.ip
          }
        },
        result: false
      });

      // Log audit event
      logAuditEvent({
        event_type: 'access_denied',
        user_id: username,
        resource: 'admin_panel',
        outcome: 'failure',
        reason: 'Admin access required'
      });

      return res.status(403).json({
        allowed: false,
        reason: 'Admin access required'
      });
    }

    // Log OPA interaction
    logOpaInteraction({
      package: 'security.access_control',
      decision: 'allow_access',
      input: {
        user: {
          id: username,
          roles: user.roles,
          status: user.status
        },
        resource: 'admin_panel',
        action: 'access_resource',
        request: {
          time: new Date().toISOString(),
          ip: req.ip
        }
      },
      result: true
    });

    // Log audit event
    logAuditEvent({
      event_type: 'admin_action',
      user_id: username,
      resource: 'admin_panel',
      outcome: 'success'
    });

    return res.status(200).json({
      allowed: true,
      admin_panel: {
        users: Object.keys(users).length,
        system_status: 'healthy'
      }
    });
  } catch (error) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token'
    });
  }
});

// Input validation endpoint
app.post('/submit_data', (req, res) => {
  const { field_type, data } = req.body;
  
  // Log OPA interaction
  const opaInput = {
    field_type: field_type,
    request: {
      data: data
    }
  };

  // Check for SQL injection
  const sqlPatterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', '--', ';'];
  const hasSqlInjection = sqlPatterns.some(pattern => 
    data.toUpperCase().includes(pattern)
  );

  if (hasSqlInjection) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'sql_injection_detected',
      input: opaInput,
      result: true
    });

    return res.status(400).json({
      valid: false,
      reason: 'SQL injection detected'
    });
  }

  // Check for XSS
  const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'eval('];
  const hasXss = xssPatterns.some(pattern => 
    data.toLowerCase().includes(pattern)
  );

  if (hasXss) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'xss_detected',
      input: opaInput,
      result: true
    });

    return res.status(400).json({
      valid: false,
      reason: 'XSS detected'
    });
  }

  // Check input length
  const maxLengths = {
    username: 50,
    password: 128,
    email: 100,
    name: 100,
    address: 200,
    phone: 20,
    comment: 500,
    text: 1000,
    date: 10
  };

  if (maxLengths[field_type] && data.length > maxLengths[field_type]) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'input_length_valid',
      input: opaInput,
      result: false
    });

    return res.status(400).json({
      valid: false,
      reason: `Input exceeds maximum length of ${maxLengths[field_type]} characters`
    });
  }

  // Check format for specific field types
  if (field_type === 'email' && !/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(data)) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'input_format_valid',
      input: opaInput,
      result: false
    });

    return res.status(400).json({
      valid: false,
      reason: 'Invalid email format'
    });
  }

  if (field_type === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(data)) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'input_format_valid',
      input: opaInput,
      result: false
    });

    return res.status(400).json({
      valid: false,
      reason: 'Invalid date format (should be YYYY-MM-DD)'
    });
  }

  if (field_type === 'phone' && !/^\+?[0-9]{10,15}$/.test(data)) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'input_format_valid',
      input: opaInput,
      result: false
    });

    return res.status(400).json({
      valid: false,
      reason: 'Invalid phone number format'
    });
  }

  // If all checks pass
  logOpaInteraction({
    package: 'security.input_validation',
    decision: 'input_valid',
    input: opaInput,
    result: true
  });

  return res.status(200).json({
    valid: true
  });
});

// File validation endpoint
app.post('/validate_file', (req, res) => {
  const { file } = req.body;
  
  // Known file hashes
  const knownHashes = {
    'config.json': 'a1b2c3d4e5f6g7h8i9j0',
    'app.js': '1a2b3c4d5e6f7g8h9i0j',
    'index.html': 'abcdef1234567890'
  };

  // Log OPA interaction
  const opaInput = {
    file: file
  };

  // Check if file hash matches known hash
  if (knownHashes[file.name] && knownHashes[file.name] === file.hash) {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'file_integrity_valid',
      input: opaInput,
      result: true
    });

    return res.status(200).json({
      valid: true
    });
  } else {
    logOpaInteraction({
      package: 'security.input_validation',
      decision: 'file_integrity_valid',
      input: opaInput,
      result: false
    });

    return res.status(400).json({
      valid: false,
      reason: 'File integrity check failed'
    });
  }
});

// TLS information endpoint
app.get('/tls_info', (req, res) => {
  return res.status(200).json({
    tls_version: 'TLS 1.3',
    cipher_suite: 'TLS_AES_256_GCM_SHA384'
  });
});

// Storage information endpoint
app.get('/storage_info', (req, res) => {
  return res.status(200).json({
    encryption_algorithm: 'AES-256',
    key_management: 'enterprise_kms'
  });
});

// Configuration change endpoint
app.post('/config_change', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      allowed: false,
      reason: 'No token provided'
    });
  }

  const token = authHeader.split(' ')[1];
  const tokenParts = token.split('.');
  
  if (tokenParts.length !== 3) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token format'
    });
  }

  try {
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
    const username = payload.sub;
    const user = users[username];

    if (!user) {
      return res.status(401).json({
        allowed: false,
        reason: 'User not found'
      });
    }

    // Check if user has admin role
    if (!user.roles.includes('admin')) {
      // Log OPA interaction
      logOpaInteraction({
        package: 'security.configuration_management',
        decision: 'config_change_authorized',
        input: {
          user: {
            id: username,
            roles: user.roles
          },
          change: req.body.change,
          request: {
            time: new Date().toISOString()
          }
        },
        result: false
      });

      return res.status(403).json({
        allowed: false,
        reason: 'User not authorized to make configuration changes'
      });
    }

    // Check if change is within allowed hours
    const simulatedTime = req.query.simulate_time;
    let currentHour;
    
    if (simulatedTime) {
      const [hours] = simulatedTime.split(':').map(Number);
      currentHour = hours;
    } else {
      currentHour = new Date().getHours();
    }

    if (currentHour < 9 || currentHour >= 17) {
      // Log OPA interaction
      logOpaInteraction({
        package: 'security.configuration_management',
        decision: 'config_change_authorized',
        input: {
          user: {
            id: username,
            roles: user.roles
          },
          change: req.body.change,
          request: {
            time: new Date().toISOString()
          }
        },
        result: false
      });

      return res.status(403).json({
        allowed: false,
        reason: 'Configuration changes are only allowed during business hours (9am-5pm)'
      });
    }

    // Check if change has required fields
    const { change } = req.body;
    if (!change || !change.ticket_id || !change.approved_by) {
      // Log OPA interaction
      logOpaInteraction({
        package: 'security.configuration_management',
        decision: 'config_change_authorized',
        input: {
          user: {
            id: username,
            roles: user.roles
          },
          change: req.body.change,
          request: {
            time: new Date().toISOString()
          }
        },
        result: false
      });

      return res.status(400).json({
        allowed: false,
        reason: 'Change request missing required fields (ticket_id, approved_by)'
      });
    }

    // Log OPA interaction
    logOpaInteraction({
      package: 'security.configuration_management',
      decision: 'config_change_authorized',
      input: {
        user: {
          id: username,
          roles: user.roles
        },
        change: req.body.change,
        request: {
          time: new Date().toISOString()
        }
      },
      result: true
    });

    // Log audit event
    logAuditEvent({
      event_type: 'configuration_change',
      user_id: username,
      resource: change.component,
      setting: change.setting,
      old_value: change.old_value,
      new_value: change.value,
      ticket_id: change.ticket_id,
      approved_by: change.approved_by,
      outcome: 'success'
    });

    return res.status(200).json({
      allowed: true,
      change_id: Math.random().toString(36).substring(2)
    });
  } catch (error) {
    return res.status(401).json({
      allowed: false,
      reason: 'Invalid token'
    });
  }
});

// Check compliance endpoint
app.post('/check_compliance', (req, res) => {
  const { component } = req.body;
  
  // Baseline configurations
  const baselines = {
    'web_server': {
      settings: [
        {name: 'max_connections', value: 1000},
        {name: 'timeout', value: 60},
        {name: 'ssl_enabled', value: true},
        {name: 'min_tls_version', value: 'TLS 1.2'},
        {name: 'default_charset', value: 'UTF-8'}
      ]
    },
    'database': {
      settings: [
        {name: 'max_connections', value: 100},
        {name: 'query_timeout', value: 30},
        {name: 'encryption_enabled', value: true},
        {name: 'backup_enabled', value: true}
      ]
    }
  };

  // Get baseline for component type
  const baseline = baselines[component.type];
  if (!baseline) {
    return res.status(400).json({
      compliant: false,
      reason: `No baseline defined for component type: ${component.type}`
    });
  }

  // Check each setting against the baseline
  const nonCompliantSettings = [];
  for (const setting of baseline.settings) {
    if (component.settings[setting.name] !== setting.value) {
      nonCompliantSettings.push(setting.name);
    }
  }

  // Log OPA interaction
  logOpaInteraction({
    package: 'security.configuration_management',
    decision: 'config_compliant_with_baseline',
    input: {
      component: component
    },
    result: nonCompliantSettings.length === 0
  });

  if (nonCompliantSettings.length === 0) {
    return res.status(200).json({
      compliant: true
    });
  } else {
    return res.status(200).json({
      compliant: false,
      non_compliant_settings: nonCompliantSettings
    });
  }
});

// Check inventory endpoint
app.post('/check_inventory', (req, res) => {
  const { component } = req.body;
  
  // Inventory
  const inventory = {
    'web-server-01': {
      type: 'web_server',
      version: '1.2.3',
      last_updated: '2023-01-15T12:00:00Z'
    },
    'db-server-01': {
      type: 'database',
      version: '4.5.6',
      last_updated: '2023-01-10T09:30:00Z'
    }
  };

  // Check if component is in inventory
  const inInventory = inventory[component.id] !== undefined;

  // Log OPA interaction
  logOpaInteraction({
    package: 'security.configuration_management',
    decision: 'component_in_inventory',
    input: {
      component: component
    },
    result: inInventory
  });

  return res.status(200).json({
    in_inventory: inInventory
  });
});

// Check dependencies endpoint
app.post('/check_dependencies', (req, res) => {
  const { component } = req.body;
  
  // Approved dependencies
  const approvedDependencies = [
    'express@4.18.2',
    'react@18.2.0',
    'node@18.12.1',
    'postgresql@14.5',
    'nginx@1.22.1'
  ];

  // Check if all dependencies are approved
  const unapprovedDependencies = component.dependencies.filter(
    dep => !approvedDependencies.includes(dep)
  );

  // Log OPA interaction
  logOpaInteraction({
    package: 'security.configuration_management',
    decision: 'dependencies_approved',
    input: {
      component: component
    },
    result: unapprovedDependencies.length === 0
  });

  if (unapprovedDependencies.length === 0) {
    return res.status(200).json({
      approved: true
    });
  } else {
    return res.status(200).json({
      approved: false,
      unapproved_dependencies: unapprovedDependencies
    });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Mock server listening at http://localhost:${port}`);
});
