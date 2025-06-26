package auth

import (
	"net/http"
	"reflect"
	"testing"
)

// TestGetAPIKey uses table-driven tests to ensure the GetAPIKey function behaves as expected.
func TestGetAPIKey(t *testing.T) {
	// Define the test cases
	testCases := []struct {
		name    string      // The name of the test case
		headers http.Header // The http.Header to pass to the function
		wantKey string      // The expected API key to be returned
		wantErr error       // The expected error to be returned
	}{
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			wantKey: "my-secret-api-key",
			wantErr: nil,
		},
		{
			name:    "No Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			wantKey: "",
			wantErr: &malformedAuthError{}, // Using a custom error type for comparison
		},
		{
			name: "Malformed header - no space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-secret-api-key"},
			},
			wantKey: "",
			wantErr: &malformedAuthError{},
		},
		{
			name: "Malformed header - only one part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: &malformedAuthError{},
		},
		{
			name: "Empty header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
	}

	// Iterate over the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function under test
			gotKey, gotErr := GetAPIKey(tc.headers)

			// Check if the returned key matches the expected key
			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() got key = %v, want %v", gotKey, tc.wantKey)
			}

			// Check if the returned error matches the expected error.
			// We use reflect.TypeOf to compare error types for the malformed error case,
			// as the error message is created dynamically.
			if tc.wantErr != nil {
				if gotErr == nil {
					t.Errorf("GetAPIKey() expected error but got nil")
				} else if reflect.TypeOf(gotErr) != reflect.TypeOf(tc.wantErr) && gotErr.Error() != tc.wantErr.Error() {
					t.Errorf("GetAPIKey() got error type = %T, want %T", gotErr, tc.wantErr)
				}
			} else if gotErr != nil {
				t.Errorf("GetAPIKey() got error = %v, want nil", gotErr)
			}
		})
	}
}

// malformedAuthError is a dummy error type for comparison in tests.
// This is because the original function returns a generic error created with errors.New().
// In a real-world scenario, you might define a specific error type for this case.
type malformedAuthError struct{}

func (m *malformedAuthError) Error() string {
	return "malformed authorization header"
}
