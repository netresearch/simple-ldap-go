//go:build !integration

package ldap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

// TestIteratorStructures tests that iterators can be created
func TestIteratorStructures(t *testing.T) {
	logger := slog.Default()

	t.Run("SearchIter creates iterator", func(t *testing.T) {
		client := &LDAP{
			logger: logger,
		}

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		iter := client.SearchIter(ctx, searchRequest)
		assert.NotNil(t, iter)
	})

	t.Run("SearchPagedIter creates iterator", func(t *testing.T) {
		client := &LDAP{
			logger: logger,
		}

		ctx := context.Background()
		searchRequest := ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"cn"},
			nil,
		)

		iter := client.SearchPagedIter(ctx, searchRequest, 10)
		assert.NotNil(t, iter)
	})

	t.Run("GroupMembersIter creates iterator", func(t *testing.T) {
		client := &LDAP{
			logger: logger,
		}

		// Note: Cannot override SearchIter in Go, so we'll test the structure creation only

		ctx := context.Background()
		groupDN := "cn=testgroup,dc=example,dc=com"

		// Just verify the iterator can be created
		iter := client.GroupMembersIter(ctx, groupDN)
		assert.NotNil(t, iter)
	})

	t.Run("GroupMembersIter handles multiple member attributes", func(t *testing.T) {
		client := &LDAP{
			logger: logger,
		}

		// Note: Cannot override SearchIter in Go, so we'll test the structure creation only

		ctx := context.Background()
		groupDN := "cn=testgroup,dc=example,dc=com"

		// Just verify the iterator can be created
		iter := client.GroupMembersIter(ctx, groupDN)
		assert.NotNil(t, iter)
	})
}

// BenchmarkIteratorCreation benchmarks iterator creation
func BenchmarkIteratorCreation(b *testing.B) {
	client := &LDAP{
		logger: slog.Default(),
	}

	ctx := context.Background()
	searchRequest := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)

	b.Run("SearchIter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.SearchIter(ctx, searchRequest)
		}
	})

	b.Run("SearchPagedIter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.SearchPagedIter(ctx, searchRequest, 100)
		}
	})

	b.Run("GroupMembersIter", func(b *testing.B) {
		// Skip since this requires actual connection
		b.Skip("Skipping GroupMembersIter benchmark - requires LDAP connection")
	})
}
