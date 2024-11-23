### 1. applications (Revised)
| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| id | UUID | Primary key | 7a1b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p |
| name | VARCHAR(255) | Application name | chrome.exe |
| publisher | VARCHAR(255) | Software publisher | Google LLC |
| created_at | TIMESTAMP | First seen | 2024-11-01 09:00:00 |
| updated_at | TIMESTAMP | Last update | 2024-11-14 10:30:00 |

### 2. application_instances
| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| id | UUID | Primary key | 8b9c0d1e-2f3g-4h5i-6j7k-8l9m0n1o2p3q |
| app_id | UUID | Reference to applications | 7a1b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p |
| endpoint_id | UUID | Reference to endpoints | 550e8400-e29b-41d4-a716-446655440000 |
| path | VARCHAR(512) | Installation path | C:\Program Files\Google\Chrome\Application\chrome.exe |
| file_hash | VARCHAR(64) | SHA-256 hash | 8a1f7b4c3d2e5a6b... |
| version | VARCHAR(50) | Application version | 98.0.4758.102 |
| created_at | TIMESTAMP | First seen | 2024-11-01 09:00:00 |
| updated_at | TIMESTAMP | Last update | 2024-11-14 10:30:00 |

### 3. policy_templates
| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| id | UUID | Primary key | 9c0d1e2f-3g4h-5i6j-7k8l-9m0n1o2p3q4r |
| name | VARCHAR(255) | Template name | Standard Browser Policy |
| description | TEXT | Policy description | Default policy for web browsers |
| created_at | TIMESTAMP | Creation time | 2024-11-01 09:00:00 |
| updated_at | TIMESTAMP | Last update | 2024-11-14 10:30:00 |

### 4. policy_rules
| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| id | UUID | Primary key | 0d1e2f3g-4h5i-6j7k-8l9m-0n1o2p3q4r5s |
| policy_template_id | UUID | Reference to policy_templates | 9c0d1e2f-3g4h-5i6j-7k8l-9m0n1o2p3q4r |
| rule_type | VARCHAR(20) | Type of rule | DOMAIN |
| rule_value | VARCHAR(255) | Rule content | *.google.com |
| protocol | VARCHAR(20) | Network protocol | TCP |
| port_range | VARCHAR(50) | Port specification | 80,443 |
| action | VARCHAR(20) | Allow/Deny | ALLOW |
| priority | INTEGER | Rule priority | 100 |
| created_at | TIMESTAMP | Creation time | 2024-11-01 09:00:00 |

### 5. instance_policies
| Column Name | Type | Description | Example |
|------------|------|-------------|---------|
| id | UUID | Primary key | 1e2f3g4h-5i6j-7k8l-9m0n-1o2p3q4r5s6t |
| app_instance_id | UUID | Reference to application_instances | 8b9c0d1e-2f3g-4h5i-6j7k-8l9m0n1o2p3q |
| policy_template_id | UUID | Reference to policy_templates | 9c0d1e2f-3g4h-5i6j-7k8l-9m0n1o2p3q4r |
| override_rules | JSONB | Instance-specific rule overrides | {"allow": ["custom-domain.com"], "deny": ["bad-domain.com"]} |
| created_at | TIMESTAMP | Assignment time | 2024-11-01 09:00:00 |
| updated_at | TIMESTAMP | Last update | 2024-11-14 10:30:00 |
