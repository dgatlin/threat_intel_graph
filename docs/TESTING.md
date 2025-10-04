# Testing Coverage - Threat Intelligence Graph

## Overview

This document outlines the testing infrastructure and coverage for the Threat Intelligence Graph project.

## Test Structure

```
tests/
├── conftest.py              # Pytest configuration and shared fixtures
├── unit/                     # Unit tests for individual components
│   ├── test_models.py        # Data model validation tests
│   ├── test_ioc_service.py   # IOC service logic tests
│   ├── test_feed_ingestion.py# Threat feed ingestion tests
│   └── test_neo4j_connection.py# Database connection tests
├── integration/              # Integration tests
│   └── test_api_integration.py# API endpoint integration tests
├── fixtures/                 # Test data fixtures
└── mocks/                    # Mock objects for testing

scripts/
├── test_otx.py              # OTX feed integration test
└── test_abuse_ch.py         # Abuse.ch feed integration test
```

## Current Test Coverage

### ✅ **Completed Test Suites:**

#### **1. Unit Tests - Data Models** (`tests/unit/test_models.py`)
- IOC model creation and validation
- IOC search request validation
- Asset threat context validation
- Threat actor model validation
- Campaign model validation
- **Status**: 7/13 tests passing (54%)

#### **2. Unit Tests - IOC Service** (`tests/unit/test_ioc_service.py`)
- Threat level calculation logic
- Asset threat context retrieval
- IOC search with filters
- IOC creation
- IOC-asset correlation
- Error handling for all operations
- **Status**: 14 test cases created

#### **3. Unit Tests - Feed Ingestion** (`tests/unit/test_feed_ingestion.py`)
- OTX feed ingestion logic
- Abuse.ch feed ingestion (Feodo, SSLBL, URLhaus)
- HTTP error handling
- Feed aggregation
- **Status**: 10 test cases created

#### **4. Unit Tests - Neo4j Connection** (`tests/unit/test_neo4j_connection.py`)
- Connection establishment and closing
- Query execution (read/write)
- Error handling
- Connection status checking
- **Status**: 10 test cases created

#### **5. Integration Tests - API** (`tests/integration/test_api_integration.py`)
- Health check endpoint
- IOC search endpoints with filters
- IOC creation
- Asset threat context
- Risk score enhancement
- Error handling and validation
- **Status**: 15 test cases created

#### **6. Integration Tests - Threat Feeds** (`scripts/`)
- OTX feed integration (`test_otx.py`)
- Abuse.ch feed integration (`test_abuse_ch.py`)
- **Status**: ✅ Both working and tested

## Test Fixtures

Located in `tests/conftest.py`:
- `mock_neo4j_driver`: Mocked Neo4j driver
- `mock_neo4j_connection`: Mocked database connection
- `sample_ioc_data`: Sample IOC for testing
- `sample_threat_actor_data`: Sample threat actor
- `sample_campaign_data`: Sample campaign
- `sample_otx_pulse`: Sample OTX pulse data
- `sample_abuse_ch_data`: Sample Abuse.ch feed data
- `mock_kafka_producer`: Mocked Kafka producer
- `mock_kafka_consumer`: Mocked Kafka consumer
- `mock_httpx_client`: Mocked HTTP client

## Running Tests

### Run All Tests
```bash
make test
# or
pytest tests/ -v
```

### Run Specific Test Suites
```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# Specific test file
pytest tests/unit/test_models.py -v

# Specific test class
pytest tests/unit/test_models.py::TestIOCModel -v

# Specific test
pytest tests/unit/test_models.py::TestIOCModel::test_ioc_creation_valid -v
```

### Run with Coverage
```bash
pytest tests/ -v --cov=api --cov=data --cov=database --cov-report=html
```

### Run Feed Integration Tests
```bash
# OTX feed test
python scripts/test_otx.py

# Abuse.ch feed test
python scripts/test_abuse_ch.py
```

## Test Coverage Metrics

| Component | Test Files | Test Cases | Status |
|-----------|-----------|------------|--------|
| **API Endpoints** | 1 | 15 | ✅ Created |
| **Data Models** | 1 | 13 | 🟡 7/13 Passing |
| **IOC Service** | 1 | 14 | ✅ Created |
| **Feed Ingestion** | 1 | 10 | ✅ Created |
| **Neo4j Connection** | 1 | 10 | ✅ Created |
| **Feed Integration** | 2 | 2 | ✅ Working |
| **Overall** | **7** | **64** | **~85% Created** |

## Known Issues

### Model Validation Tests
Some model tests are failing due to:
1. Enum value mismatches (`IP` vs `IP_ADDRESS`, `C2` vs `command_and_control`)
2. Missing required fields in test fixtures (`source`, `confidence`)

**Fix Required**: Update test fixtures to match actual model schemas.

### Neo4j Connection Tests
- Tests require Neo4j to NOT be running (uses mocks)
- Connection is now lazy-initialized to avoid import-time connection attempts

## Testing Best Practices

1. **Unit Tests**: Test individual components in isolation with mocked dependencies
2. **Integration Tests**: Test component interactions with minimal mocking
3. **Fixtures**: Use shared fixtures from `conftest.py` for consistency
4. **Mocking**: Mock external dependencies (Neo4j, Kafka, HTTP clients)
5. **Async Tests**: Use `@pytest.mark.asyncio` for async functions
6. **Error Handling**: Test both success and failure paths

## Future Testing Enhancements

### High Priority
- [ ] Fix model validation test failures
- [ ] Add Kafka stream processing tests
- [ ] Add end-to-end integration tests
- [ ] Add performance/load tests

### Medium Priority
- [ ] Add threat actor service tests
- [ ] Add campaign service tests
- [ ] Add configuration validation tests
- [ ] Add logging tests

### Low Priority
- [ ] Add stress tests for graph queries
- [ ] Add security/penetration tests
- [ ] Add API rate limiting tests
- [ ] Add data validation tests

## Continuous Integration

### GitHub Actions Workflow (Planned)
```yaml
- Run linters (black, flake8, mypy)
- Run unit tests
- Run integration tests (with Docker Neo4j)
- Generate coverage reports
- Upload coverage to Codecov
```

## Test Data Management

- **Test Fixtures**: Located in `tests/conftest.py`
- **Mock Data**: Generated programmatically in fixtures
- **Real Data**: Use `scripts/test_*.py` for real feed integration
- **Database**: Tests use mocked Neo4j connection (no database required for unit tests)

## Dependencies

Testing dependencies in `requirements.txt`:
```
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
pytest-mock==3.12.0
```

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure tests pass locally
3. Update this document with new test coverage
4. Maintain minimum 80% code coverage

## Contact

For questions about testing:
- Review test documentation in code
- Check pytest documentation: https://docs.pytest.org/
- See existing test examples in `tests/`
