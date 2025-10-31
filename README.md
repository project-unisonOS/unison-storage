# unison-storage

The storage service provides secure, partitioned data persistence for the Unison platform, handling working memory, long-term storage, and sensitive data protection.

## Purpose

The storage service:
- Provides ephemeral working memory for active sessions and operations
- Manages long-term personal memory with encryption and retention controls
- Operates a secure vault for credentials, tokens, and sensitive data
- Maintains comprehensive audit logs for compliance and security
- Ensures data privacy through encryption and access controls
- Supports backup, recovery, and data portability

## Current Status

### ✅ Implemented
- FastAPI-based HTTP service with health endpoints
- Encrypted data storage with AES-256 encryption
- Working memory for session management
- Secure vault for sensitive data storage
- Comprehensive audit logging with correlation IDs
- Data retention and deletion policies
- Access controls and authentication integration
- Backup and recovery capabilities
- Network-segmented deployment configuration

### 🚧 In Progress
- Advanced compression and deduplication
- Multi-region data replication
- Real-time data synchronization
- Advanced analytics and insights

### 📋 Planned
- Data lifecycle management automation
- Cross-cloud data migration
- Advanced search and indexing
- Machine learning-based data optimization

## Quick Start

### Local Development
```bash
# Clone and setup
git clone https://github.com/project-unisonOS/unison-storage
cd unison-storage

# Install dependencies
pip install -r requirements.txt

# Run with default configuration
export STORAGE_ENCRYPTION_KEY="your-256-bit-key"
python src/server.py
```

### Docker Deployment
```bash
# Using the development stack
cd ../unison-devstack
docker-compose up -d storage

# Health check
curl http://localhost:8082/health
```

### Security-Hardened Deployment
```bash
# Using the security configuration
cd ../unison-devstack
docker-compose -f docker-compose.security.yml up -d

# Access through internal network
curl http://storage:8082/health
```

## API Reference

### Core Endpoints
- `GET /health` - Service health check
- `GET /ready` - Storage system readiness check
- `POST /memory` - Store working memory data
- `GET /memory/{session_id}` - Retrieve session memory
- `DELETE /memory/{session_id}` - Clear session memory
- `POST /vault` - Store sensitive data in vault
- `GET /vault/{key_id}` - Retrieve vault data
- `POST /audit` - Log audit events
- `GET /audit` - Query audit logs

### Storage Operations
```bash
# Store working memory
curl -X POST http://localhost:8082/memory \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session-123",
    "data": {"key": "value", "context": "active"},
    "ttl": 3600
  }'

# Retrieve memory
curl -X GET http://localhost:8082/memory/session-123 \
  -H "Authorization: Bearer <access-token>"

# Store in secure vault
curl -X POST http://localhost:8082/vault \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "api-key-123",
    "data": "sensitive-data",
    "metadata": {"type": "credential", "expires": "2024-12-31"}
  }'
```

[Full API Documentation](../../unison-docs/developer/api-reference/storage.md)

## Configuration

### Environment Variables
```bash
# Service Configuration
STORAGE_PORT=8082                    # Service port
STORAGE_HOST=0.0.0.0                 # Service host

# Security Configuration
STORAGE_ENCRYPTION_KEY=your-key      # 256-bit encryption key
STORAGE_VAULT_KEY=your-vault-key     # Separate vault encryption key
STORAGE_ENABLE_AUDIT=true            # Enable audit logging

# Database Configuration
STORAGE_DATABASE_URL=postgresql://user:pass@localhost/unison
STORAGE_CONNECTION_POOL_SIZE=20      # Database connection pool
STORAGE_QUERY_TIMEOUT=30             # Query timeout in seconds

# Retention Policies
STORAGE_MEMORY_TTL=3600              # Working memory TTL (seconds)
STORAGE_VAULT_TTL=86400              # Vault data TTL (seconds)
STORAGE_AUDIT_RETENTION_DAYS=365     # Audit log retention

# Performance
STORAGE_MAX_FILE_SIZE=100MB          # Maximum file size
STORAGE_COMPRESSION=true             # Enable compression
STORAGE_CACHE_SIZE=1GB               # In-memory cache size
```

## Data Model

### Working Memory Structure
```json
{
  "session_id": "session-123",
  "person_id": "person-456",
  "data": {
    "active_context": "document_editing",
    "temporary_state": {
      "cursor_position": 150,
      "selection": "selected text"
    },
    "cache": {
      "recent_queries": ["summarize", "edit"],
      "preferences": {"theme": "dark"}
    }
  },
  "metadata": {
    "created_at": "2024-01-01T12:00:00Z",
    "expires_at": "2024-01-01T13:00:00Z",
    "access_count": 5,
    "last_accessed": "2024-01-01T12:30:00Z"
  }
}
```

### Vault Data Structure
```json
{
  "key_id": "credential-123",
  "person_id": "person-456",
  "data": "encrypted_base64_data",
  "metadata": {
    "type": "api_key",
    "service": "openai",
    "created_at": "2024-01-01T12:00:00Z",
    "expires_at": "2024-12-31T23:59:59Z",
    "access_count": 0,
    "last_accessed": null
  },
  "permissions": {
    "read": ["person-456", "service-orchestrator"],
    "write": ["person-456"],
    "delete": ["person-456", "admin"]
  }
}
```

## Development

### Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Initialize database
python scripts/init_db.py

# Run tests
pytest tests/

# Run with debug logging
LOG_LEVEL=DEBUG python src/server.py
```

### Testing
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Security tests
pytest tests/security/

# Performance tests
pytest tests/performance/

# Encryption tests
pytest tests/encryption/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive tests
4. Ensure all security and privacy tests pass
5. Submit a pull request with detailed description

[Development Guide](../../unison-docs/developer/contributing.md)

## Security and Privacy

### Data Protection
- **Encryption at Rest**: AES-256 encryption for all stored data
- **Encryption in Transit**: TLS 1.2+ for all network communication
- **Key Management**: Separate encryption keys for different data types
- **Access Controls**: Role-based access with audit trails
- **Data Minimization**: Only store necessary data with clear purpose

### Privacy Controls
- **Consent Management**: Explicit consent for data collection and storage
- **Right to Delete**: Complete data deletion on request
- **Data Portability**: Export data in standard formats
- **Retention Policies**: Automatic cleanup based on configured policies
- **Audit Logging**: Comprehensive logging of all data operations

### Compliance
- **GDPR Compliance**: Full compliance with data protection regulations
- **SOC 2 Controls**: Security and compliance controls implemented
- **Data Residency**: Control over data storage location
- **Breach Notification**: Automated breach detection and notification

[Security Documentation](../../unison-docs/operations/security.md)

## Architecture

### Storage Service Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Layer     │───▶│  Business Logic  │───▶│  Storage Layer  │
│ (FastAPI)       │    │ (Data Manager)   │    │ (Database)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Security Layer  │
                       │ (Encryption &    │
                       │  Access Control) │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Audit Layer    │
                       │ (Logging &       │
                       │  Compliance)     │
                       └──────────────────┘
```

### Data Flow
1. **Request**: Service requests storage operation
2. **Authentication**: Verify access permissions and consent
3. **Encryption**: Encrypt data before storage
4. **Storage**: Store encrypted data with metadata
5. **Audit**: Log operation for compliance
6. **Response**: Return operation confirmation

[Architecture Documentation](../../unison-docs/developer/architecture.md)

## Monitoring

### Health Checks
- `/health` - Basic service health
- `/ready` - Database connectivity and storage readiness
- `/metrics` - Storage operation metrics

### Metrics
Key metrics available:
- Storage operations per second
- Data volume by type
- Encryption/decryption performance
- Audit log volume
- Cache hit rates
- Database connection pool status

### Logging
Structured JSON logging with correlation IDs:
- Data access and modifications
- Security events and violations
- Performance metrics and bottlenecks
- Error tracking and recovery
- Compliance and audit events

[Monitoring Guide](../../unison-docs/operations/monitoring.md)

## Backup and Recovery

### Backup Strategy
```bash
# Create encrypted backup
python scripts/backup.py \
  --output /backups/unison-$(date +%Y%m%d). encrypted \
  --compress

# Verify backup integrity
python scripts/verify_backup.py \
  --input /backups/unison-20240101.encrypted

# Restore from backup
python scripts/restore.py \
  --input /backups/unison-20240101.encrypted \
  --target-date "2024-01-01"
```

### Disaster Recovery
- **Point-in-Time Recovery**: Restore to specific timestamp
- **Selective Recovery**: Restore specific data types or sessions
- **Cross-Region Recovery**: Restore from alternative region backups
- **Validation**: Automated integrity checks after recovery

[Backup and Recovery Guide](../../unison-docs/operations/backup-recovery.md)

## Related Services

### Dependencies
- **unison-auth** - Authentication and authorization
- **unison-orchestrator** - Primary storage consumer
- **unison-context** - Context data storage and retrieval

### Consumers
- **unison-orchestrator** - Working memory and session storage
- **unison-context** - Long-term context and preferences
- **unison-policy** - Policy decisions and audit logs
- **unison-inference** - Model caching and results storage

## Troubleshooting

### Common Issues

**Storage Not Responding**
```bash
# Check service health
curl http://localhost:8082/health

# Verify database connectivity
curl http://localhost:8082/ready

# Check database connection pool
docker-compose logs storage | grep "database"
```

**Encryption/Decryption Errors**
```bash
# Verify encryption key
grep STORAGE_ENCRYPTION_KEY .env

# Test encryption functionality
python scripts/test_encryption.py

# Check key rotation status
curl -X GET http://localhost:8082/keys/status \
  -H "Authorization: Bearer <token>"
```

**Performance Issues**
```bash
# Check storage metrics
curl http://localhost:8082/metrics

# Monitor query performance
docker-compose logs storage | grep "slow_query"

# Check cache efficiency
curl -X GET http://localhost:8082/cache/stats \
  -H "Authorization: Bearer <token>"
```

### Debug Mode
```bash
# Enable verbose logging
LOG_LEVEL=DEBUG STORAGE_DEBUG_QUERIES=true python src/server.py

# Monitor storage operations
docker-compose logs -f storage | jq '.'

# Test storage functionality
python scripts/diagnostic.py --all
```

[Troubleshooting Guide](../../unison-docs/people/troubleshooting.md)

## Version Compatibility

| Storage Version | Unison Common | Auth Service | Minimum Docker |
|-----------------|---------------|--------------|----------------|
| 1.0.0           | 1.0.0         | 1.0.0        | 20.10+         |
| 0.9.x           | 0.9.x         | 0.9.x        | 20.04+         |

[Compatibility Matrix](../../unison-spec/specs/version-compatibility.md)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [Project Unison Docs](https://github.com/project-unisonOS/unison-docs)
- **Issues**: [GitHub Issues](https://github.com/project-unisonOS/unison-storage/issues)
- **Discussions**: [GitHub Discussions](https://github.com/project-unisonOS/unison-storage/discussions)
- **Security**: Report security issues to security@unisonos.org
