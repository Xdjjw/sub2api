package repository

import (
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/stretchr/testify/require"
)

func TestGroupListOrderShieldEnabled(t *testing.T) {
	tests := []struct {
		name      string
		sortOrder string
		want      string
	}{
		{
			name:      "ascending",
			sortOrder: "asc",
			want:      `SELECT * FROM "groups" ORDER BY "groups"."shield_enabled" ASC, "groups"."id" ASC`,
		},
		{
			name:      "descending",
			sortOrder: "desc",
			want:      `SELECT * FROM "groups" ORDER BY "groups"."shield_enabled" DESC, "groups"."id" DESC`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := entsql.Dialect(dialect.Postgres).
				Select().
				From(entsql.Table("groups"))
			for _, order := range groupListOrder(pagination.PaginationParams{
				SortBy:    "shield_enabled",
				SortOrder: tt.sortOrder,
			}) {
				order(selector)
			}

			query, args := selector.Query()
			require.Empty(t, args)
			require.Equal(t, tt.want, query)
		})
	}
}
