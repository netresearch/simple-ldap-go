package ldap

import (
	"context"
	"iter"

	"github.com/go-ldap/ldap/v3"
)

// SearchIter performs an LDAP search and returns an iterator over the results.
// This allows for memory-efficient processing of large result sets.
// The iterator supports early termination by the caller.
func (l *LDAP) SearchIter(ctx context.Context, searchRequest *ldap.SearchRequest) iter.Seq2[*ldap.Entry, error] {
	return func(yield func(*ldap.Entry, error) bool) {
		// Get connection
		conn, err := l.GetConnection()
		if err != nil {
			yield(nil, err)
			return
		}
		defer conn.Close()

		// Perform the search
		result, err := conn.Search(searchRequest)
		if err != nil {
			yield(nil, err)
			return
		}

		// Iterate over entries
		for _, entry := range result.Entries {
			if !yield(entry, nil) {
				// Caller terminated iteration early
				return
			}
		}
	}
}

// SearchPagedIter performs a paged LDAP search and returns an iterator.
// This is more memory-efficient for very large result sets as it fetches
// results in chunks from the server.
func (l *LDAP) SearchPagedIter(ctx context.Context, searchRequest *ldap.SearchRequest, pageSize uint32) iter.Seq2[*ldap.Entry, error] {
	return func(yield func(*ldap.Entry, error) bool) {
		conn, err := l.GetConnection()
		if err != nil {
			yield(nil, err)
			return
		}
		defer conn.Close()

		pagingControl := ldap.NewControlPaging(pageSize)
		controls := []ldap.Control{pagingControl}

		for {
			searchRequest.Controls = controls
			response, err := conn.Search(searchRequest)
			if err != nil {
				yield(nil, err)
				return
			}

			// Yield entries from this page
			for _, entry := range response.Entries {
				if !yield(entry, nil) {
					// Caller terminated iteration early
					return
				}
			}

			// Check for paging control in response
			pagingResult := ldap.FindControl(response.Controls, ldap.ControlTypePaging)
			if ctrl, ok := pagingResult.(*ldap.ControlPaging); ok {
				if len(ctrl.Cookie) == 0 {
					// No more pages
					break
				}
				// Update cookie for next page
				pagingControl.SetCookie(ctrl.Cookie)
			} else {
				// No paging control in response, we're done
				break
			}
		}
	}
}

// GroupMembersIter returns an iterator over group members.
// This efficiently handles large groups without loading all members into memory.
func (l *LDAP) GroupMembersIter(ctx context.Context, groupDN string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		searchRequest := ldap.NewSearchRequest(
			groupDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"member", "memberUid", "uniqueMember"},
			nil,
		)

		for entry, err := range l.SearchIter(ctx, searchRequest) {
			if err != nil {
				yield("", err)
				return
			}

			// Yield each member
			members := append(
				entry.GetAttributeValues("member"),
				entry.GetAttributeValues("memberUid")...,
			)
			members = append(members, entry.GetAttributeValues("uniqueMember")...)

			for _, member := range members {
				if !yield(member, nil) {
					return
				}
			}
		}
	}
}