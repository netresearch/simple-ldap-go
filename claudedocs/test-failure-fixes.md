# Test Failure Fixes - Action Plan

## Summary
Systematically fixing all remaining test failures in the simple-ldap-go project.

## Priority 1: Critical Infrastructure Issues

### 1. Missing Error Constants
- **Issue**: `ErrAccountDisabled` is referenced but not defined
- **Location**: `/srv/www/sme/simple-ldap-go/errors.go`
- **Fix**: Add missing error constant to error definitions

### 2. Context Handling Implementation
- **Issue**: `GetConnectionContext` returns "connection not implemented" instead of checking context
- **Files**:
  - `/srv/www/sme/simple-ldap-go/client.go` - `GetConnectionContext`
  - All `*Context` methods need proper context cancellation checks
- **Fix**: Implement proper context checking using existing `checkContextCancellation` utility

### 3. Error Formatting Masking
- **Issue**: `FormatErrorWithContext` is over-masking sensitive data in tests
- **Location**: `/srv/www/sme/simple-ldap-go/errors.go` - `FormatErrorWithContext`
- **Fix**: Adjust masking logic to preserve test data visibility

## Priority 2: Validation Functions

### 4. Computer SAMAccountName Validation
- **Issue**: Computer name validation incorrectly rejecting valid format `computer01$`
- **Location**: Computer validation functions
- **Fix**: Update computer name validation logic

### 5. Validation Helper Functions
- **Issues**:
  - `TestValidateLDAPFilter` failing
  - `TestValidateSAMAccountName` failing
  - `TestValidateEmail` failing
  - `TestValidateServerURL` failing
- **Fix**: Implement or fix validation functions

## Priority 3: Logging Infrastructure

### 6. Structured Logging Tests
- **Issues**:
  - `TestStructuredLoggingConfiguration` failing
  - `TestNoOpLogger` failing
  - `TestLogLevels` failing
  - Various logging tests failing
- **Fix**: Implement missing logging functionality

## Priority 4: Builder Patterns

### 7. Builder Pattern Validation
- **Issue**: UserBuilder validation logic incorrect
- **Location**: Modern builder pattern implementation
- **Fix**: Fix builder validation order and logic

## Priority 5: Example Tests

### 8. Example Output Matching
- **Issues**:
  - `Example_connectionPooling` output mismatch
  - `Example_backwardCompatibility` output mismatch
  - `Example_poolConfiguration` output mismatch
- **Fix**: Update example outputs or implementation

## Execution Strategy
1. Fix infrastructure issues first (errors, context handling)
2. Fix validation functions
3. Implement logging infrastructure
4. Fix builder patterns
5. Update example outputs

Each fix will be tested immediately to ensure no regressions.