# Test Fixes TODO List

## Failing Tests to Fix

### Error Handling Tests
- [ ] TestLDAPError - maskSensitiveData masking DN/server in error messages
- [ ] TestFormatErrorWithContext - needs FormatErrorWithContext function
- [ ] TestContextCancellation - context methods not checking context.Done()
- [ ] TestContextDeadlineExceeded - context methods not checking context.Done()

### Validation Tests
- [ ] TestValidateLDAPFilter - overly complex filter validation too permissive
- [ ] TestValidateSAMAccountName - needs implementation
- [ ] TestValidateEmail - needs implementation
- [ ] TestValidateServerURL - needs implementation

### Computer Tests
- [ ] TestComputerSAMAccountNameFormat - test logic incorrect for computer names

### Builder Pattern Tests
- [ ] TestBuilderPatterns - needs implementation

### Logging Tests
- [ ] TestStructuredLoggingConfiguration - needs implementation
- [ ] TestNoOpLogger - needs implementation
- [ ] TestLogLevels - needs implementation
- [ ] TestAuthenticationLogging - needs implementation
- [ ] TestSearchOperationLogging - needs implementation
- [ ] TestLogSecurity - needs implementation
- [ ] TestPerformanceLogging - needs implementation

### Utility Tests
- [ ] TestParseObjectEnabled - needs implementation
- [ ] TestUtilsErrorHandling - needs implementation
- [ ] TestValidator_ValidateFilter - needs implementation
- [ ] TestValidator_ValidateAttribute - needs implementation
- [ ] TestPasswordAnalysis - needs implementation

### Example Tests
- [ ] Example_connectionPooling - needs implementation
- [ ] Example_backwardCompatibility - needs implementation
- [ ] Example_poolConfiguration - needs implementation

## Implementation Strategy
1. Fix error masking for test expectations
2. Implement missing context checking in methods
3. Add missing validation functions
4. Implement missing logging functionality
5. Add missing utility functions
6. Fix test logic issues