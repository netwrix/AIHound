package scanners

import (
	"aihound/core"
	"sort"
)

var registry = make(map[string]core.Scanner)

// Register adds a scanner to the global registry, keyed by its slug.
// Scanner implementations should call this from their init() functions.
func Register(s core.Scanner) {
	registry[s.Slug()] = s
}

// GetAll returns all registered scanners, sorted by slug for deterministic ordering.
func GetAll() []core.Scanner {
	scanners := make([]core.Scanner, 0, len(registry))
	for _, s := range registry {
		scanners = append(scanners, s)
	}
	sort.Slice(scanners, func(i, j int) bool {
		return scanners[i].Slug() < scanners[j].Slug()
	})
	return scanners
}

// GetBySlug returns the scanner registered under the given slug, or nil if not found.
func GetBySlug(slug string) core.Scanner {
	return registry[slug]
}
