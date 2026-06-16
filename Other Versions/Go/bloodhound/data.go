package bloodhound

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed data/schema.json data/queries.json
var embeddedData embed.FS

// LoadSchema loads the OpenGraph extension schema.
// If filepath is empty, uses the embedded default.
func LoadSchema(filepath string) (map[string]interface{}, error) {
	var data []byte
	var err error

	if filepath != "" {
		data, err = os.ReadFile(filepath)
	} else {
		data, err = embeddedData.ReadFile("data/schema.json")
	}
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	return schema, nil
}

// LoadQueries loads queries from a JSON file in SpecterOps Query Library format.
// If filepath is empty, uses the embedded default.
func LoadQueries(filepath string) ([]map[string]interface{}, error) {
	var data []byte
	var err error

	if filepath != "" {
		data, err = os.ReadFile(filepath)
	} else {
		data, err = embeddedData.ReadFile("data/queries.json")
	}
	if err != nil {
		return nil, fmt.Errorf("read queries: %w", err)
	}

	var queries []map[string]interface{}
	if err := json.Unmarshal(data, &queries); err != nil {
		return nil, fmt.Errorf("parse queries: %w", err)
	}
	return queries, nil
}
