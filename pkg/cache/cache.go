// Package cache provides an interface which can be implemented by different cache types.
package cache

// Cache is used to store key/value pairs.
type Cache interface {
	// Set stores the given key/value pair.
	Set(string, bool)
	// Get returns the value for the given key and a boolean indicating if the key was found.
	Get(string) (string, bool)
	// Delete the given key from the cache.
	Delete(string)
	// Clear all key/value pairs from the cache.
	Clear()
	// Count the number of key/value pairs in the cache.
	Count() int
	// Contents returns all keys in the cache encoded as a string.
	Contents() string
}