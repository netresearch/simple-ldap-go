// Package ldap provides interface segregation for better testability and modularity.
package ldap

import (
	"context"

	"github.com/go-ldap/ldap/v3"
)

// UserReader defines methods for reading user information from LDAP.
// This interface follows the Interface Segregation Principle by separating read operations.
type UserReader interface {
	// FindUserByDN retrieves a user by their distinguished name
	FindUserByDN(dn string) (*User, error)
	// FindUserByDNContext retrieves a user by their distinguished name with context
	FindUserByDNContext(ctx context.Context, dn string) (*User, error)
	// FindUserBySAMAccountName retrieves a user by their SAM account name
	FindUserBySAMAccountName(name string) (*User, error)
	// FindUserBySAMAccountNameContext retrieves a user by their SAM account name with context
	FindUserBySAMAccountNameContext(ctx context.Context, name string) (*User, error)
	// FindUserByMail retrieves a user by their email address
	FindUserByMail(mail string) (*User, error)
	// FindUserByMailContext retrieves a user by their email address with context
	FindUserByMailContext(ctx context.Context, mail string) (*User, error)
}

// UserWriter defines methods for writing/modifying user information in LDAP.
// This interface follows the Interface Segregation Principle by separating write operations.
type UserWriter interface {
	// CreateUser creates a new user with the provided information and password
	CreateUser(user FullUser, password string) (string, error)
	// CreateUserContext creates a new user with the provided information and password with context
	CreateUserContext(ctx context.Context, user FullUser, password string) (string, error)
	// DeleteUser deletes a user by their distinguished name
	DeleteUser(dn string) error
	// DeleteUserContext deletes a user by their distinguished name with context
	DeleteUserContext(ctx context.Context, dn string) error
	// UpdateUserPassword updates a user's password
	UpdateUserPassword(dn string, newPassword string) error
	// UpdateUserPasswordContext updates a user's password with context
	UpdateUserPasswordContext(ctx context.Context, dn, newPassword string) error
}

// UserManager combines UserReader and UserWriter interfaces for complete user management.
// This interface provides a comprehensive set of user management operations.
type UserManager interface {
	UserReader
	UserWriter
	// GetUserGroups retrieves the groups a user belongs to
	GetUserGroups(userDN string) ([]Group, error)
	// GetUserGroupsContext retrieves the groups a user belongs to with context
	GetUserGroupsContext(ctx context.Context, userDN string) ([]Group, error)
}

// GroupReader defines methods for reading group information from LDAP.
// This interface follows the Interface Segregation Principle by separating read operations.
type GroupReader interface {
	// FindGroupByDN retrieves a group by their distinguished name
	FindGroupByDN(dn string) (*Group, error)
	// FindGroupByDNContext retrieves a group by their distinguished name with context
	FindGroupByDNContext(ctx context.Context, dn string) (*Group, error)
	// FindGroupByCN retrieves a group by their common name
	FindGroupByCN(cn string) (*Group, error)
	// FindGroupByCNContext retrieves a group by their common name with context
	FindGroupByCNContext(ctx context.Context, cn string) (*Group, error)
}

// GroupWriter defines methods for writing/modifying group information in LDAP.
// This interface follows the Interface Segregation Principle by separating write operations.
type GroupWriter interface {
	// CreateGroup creates a new group with the provided information
	CreateGroup(group FullGroup) (string, error)
	// CreateGroupContext creates a new group with the provided information with context
	CreateGroupContext(ctx context.Context, group FullGroup) (string, error)
	// DeleteGroup deletes a group by their distinguished name
	DeleteGroup(dn string) error
	// DeleteGroupContext deletes a group by their distinguished name with context
	DeleteGroupContext(ctx context.Context, dn string) error
	// AddUserToGroup adds a user to a group
	AddUserToGroup(userDN, groupDN string) error
	// AddUserToGroupContext adds a user to a group with context
	AddUserToGroupContext(ctx context.Context, userDN, groupDN string) error
	// RemoveUserFromGroup removes a user from a group
	RemoveUserFromGroup(userDN, groupDN string) error
	// RemoveUserFromGroupContext removes a user from a group with context
	RemoveUserFromGroupContext(ctx context.Context, userDN, groupDN string) error
}

// GroupManager combines GroupReader and GroupWriter interfaces for complete group management.
// This interface provides a comprehensive set of group management operations.
type GroupManager interface {
	GroupReader
	GroupWriter
	// GetGroupMembers retrieves the members of a group
	GetGroupMembers(groupDN string) ([]User, error)
	// GetGroupMembersContext retrieves the members of a group with context
	GetGroupMembersContext(ctx context.Context, groupDN string) ([]User, error)
}

// ComputerReader defines methods for reading computer information from LDAP.
// This interface follows the Interface Segregation Principle by separating read operations.
type ComputerReader interface {
	// FindComputerByDN retrieves a computer by their distinguished name
	FindComputerByDN(dn string) (*Computer, error)
	// FindComputerByDNContext retrieves a computer by their distinguished name with context
	FindComputerByDNContext(ctx context.Context, dn string) (*Computer, error)
	// FindComputerBySAMAccountName retrieves a computer by their SAM account name
	FindComputerBySAMAccountName(name string) (*Computer, error)
	// FindComputerBySAMAccountNameContext retrieves a computer by their SAM account name with context
	FindComputerBySAMAccountNameContext(ctx context.Context, name string) (*Computer, error)
}

// ComputerWriter defines methods for writing/modifying computer information in LDAP.
// This interface follows the Interface Segregation Principle by separating write operations.
type ComputerWriter interface {
	// CreateComputer creates a new computer with the provided information
	CreateComputer(computer FullComputer) (string, error)
	// CreateComputerContext creates a new computer with the provided information with context
	CreateComputerContext(ctx context.Context, computer FullComputer) (string, error)
	// DeleteComputer deletes a computer by their distinguished name
	DeleteComputer(dn string) error
	// DeleteComputerContext deletes a computer by their distinguished name with context
	DeleteComputerContext(ctx context.Context, dn string) error
}

// ComputerManager combines ComputerReader and ComputerWriter interfaces for complete computer management.
// This interface provides a comprehensive set of computer management operations.
type ComputerManager interface {
	ComputerReader
	ComputerWriter
}

// DirectoryManager is the main interface that combines all LDAP management capabilities.
// This interface provides a unified API for all directory operations.
type DirectoryManager interface {
	UserManager
	GroupManager
	ComputerManager

	// Connection management
	GetConnection() (*ldap.Conn, error)
	GetConnectionContext(ctx context.Context) (*ldap.Conn, error)
	Close() error

	// Statistics and monitoring
	GetPoolStats() PerformanceStats
	GetCacheStats() *CacheStats
	GetPerformanceStats() PerformanceStats
	ClearCache()
}

// Ensure LDAP implements the DirectoryManager interface.
// Note: LDAP does not yet fully implement DirectoryManager (missing CreateComputer, etc.)
// Uncomment when all methods are implemented:
// var _ DirectoryManager = (*LDAP)(nil)

// ReadOnlyDirectory is a read-only interface for LDAP operations.
// This interface is useful for applications that only need read access.
type ReadOnlyDirectory interface {
	UserReader
	GroupReader
	ComputerReader

	// Connection management (read-only)
	GetConnection() (*ldap.Conn, error)
	GetConnectionContext(ctx context.Context) (*ldap.Conn, error)

	// Statistics and monitoring (read-only)
	GetPoolStats() PerformanceStats
	GetCacheStats() *CacheStats
	GetPerformanceStats() PerformanceStats
}

// WriteOnlyDirectory is a write-only interface for LDAP operations.
// This interface is useful for applications that only need write access.
type WriteOnlyDirectory interface {
	UserWriter
	GroupWriter
	ComputerWriter

	// Connection management
	GetConnection() (*ldap.Conn, error)
	GetConnectionContext(ctx context.Context) (*ldap.Conn, error)
	Close() error
}
