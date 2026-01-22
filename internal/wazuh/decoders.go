package wazuh

import (
	"encoding/json"
	"fmt"
)

// FlexibleString can unmarshal both number and string values
type FlexibleString struct {
	Value string
}

func (fs *FlexibleString) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as number first
	var num float64
	if err := json.Unmarshal(data, &num); err == nil {
		fs.Value = fmt.Sprintf("%.0f", num)
		return nil
	}
	// If not a number, unmarshal as string
	return json.Unmarshal(data, &fs.Value)
}

func (fs FlexibleString) MarshalJSON() ([]byte, error) {
	return json.Marshal(fs.Value)
}

func (fs FlexibleString) String() string {
	return fs.Value
}

// FlexibleDetails can unmarshal both []string and object values
type FlexibleDetails struct {
	Value []string
}

func (fd *FlexibleDetails) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		fd.Value = arr
		return nil
	}
	// If not an array, try to unmarshal as object
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		// Convert object to array of key-value strings
		var result []string
		for k, v := range obj {
			result = append(result, fmt.Sprintf("%s: %v", k, v))
		}
		fd.Value = result
		return nil
	}
	// If neither, try as single string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		if str != "" {
			fd.Value = []string{str}
		} else {
			fd.Value = []string{}
		}
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexibleDetails", string(data))
}

func (fd FlexibleDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(fd.Value)
}

// Decoder represents a Wazuh decoder
type Decoder struct {
	Parent      string          `json:"parent"`
	Position    FlexibleString  `json:"position"`
	Status      string          `json:"status"`
	Name        string          `json:"name"`
	Filename    string          `json:"filename"`
	Description string          `json:"description"`
	Details     FlexibleDetails `json:"details"`
	Regex       string          `json:"regex"`
	Order       int             `json:"order"`
	ProgramName string          `json:"program_name"`
}

// GetDecoders retrieves all decoders
func (c *Client) GetDecoders(limit int, offset int, search string, sort string, order string) ([]Decoder, error) {
	req := c.ManagerRequest().
		SetQueryParam("limit", fmt.Sprintf("%d", limit)).
		SetQueryParam("offset", fmt.Sprintf("%d", offset))

	if search != "" {
		req.SetQueryParam("search", search)
	}
	if sort != "" {
		req.SetQueryParam("sort", sort)
	}
	if order != "" {
		req.SetQueryParam("order", order)
	}

	resp, err := req.Get("/decoders")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting decoders: %s", resp.String())
	}

	var result struct {
		Data struct {
			AffectedItems []Decoder `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}

// GetDecoderFiles retrieves decoder files
func (c *Client) GetDecoderFiles() ([]string, error) {
	resp, err := c.ManagerRequest().Get("/decoders/files")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, fmt.Errorf("error getting decoder files: %s", resp.String())
	}

	// Try to unmarshal as standard response first
	var result struct {
		Data struct {
			AffectedItems []string `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err == nil {
		return result.Data.AffectedItems, nil
	}

	// If that fails, try to unmarshal as object and extract affected_items
	var objResult struct {
		Data struct {
			AffectedItems interface{} `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &objResult); err != nil {
		return nil, err
	}

	// If affected_items is an object, try to convert it
	if items, ok := objResult.Data.AffectedItems.([]interface{}); ok {
		var files []string
		for _, item := range items {
			if str, ok := item.(string); ok {
				files = append(files, str)
			} else if obj, ok := item.(map[string]interface{}); ok {
				// Try to extract filename or path from object
				if filename, ok := obj["filename"].(string); ok {
					files = append(files, filename)
				} else if path, ok := obj["path"].(string); ok {
					files = append(files, path)
				}
			}
		}
		return files, nil
	}

	return nil, fmt.Errorf("unexpected response format for decoder files")
}

// GetDecodersByFile retrieves decoders from a specific file
// Note: Some API versions don't support limit/offset query parameters for this endpoint
func (c *Client) GetDecodersByFile(filename string, limit int, offset int) ([]Decoder, error) {
	req := c.ManagerRequest().
		SetPathParams(map[string]string{"filename": filename})
	// Only add limit/offset if they're set - some API versions don't support these
	// Try with parameters first, fall back if they cause errors
	if limit > 0 {
		req = req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		req = req.SetQueryParam("offset", fmt.Sprintf("%d", offset))
	}

	resp, err := req.Get("/decoders/files/{filename}")
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		// If error is due to unsupported query parameters, try without them
		if (limit > 0 || offset > 0) && (resp.StatusCode() == 400 || resp.StatusCode() == 422) {
			resp, err = c.ManagerRequest().
				SetPathParams(map[string]string{"filename": filename}).
				Get("/decoders/files/{filename}")
			if err != nil {
				return nil, err
			}
			if resp.IsError() {
				return nil, fmt.Errorf("error getting decoders by file: %s", resp.String())
			}
		} else {
			return nil, fmt.Errorf("error getting decoders by file: %s", resp.String())
		}
	}

	var result struct {
		Data struct {
			AffectedItems []Decoder `json:"affected_items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result.Data.AffectedItems, nil
}
