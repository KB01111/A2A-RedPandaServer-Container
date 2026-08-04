package postgres

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func encodePageToken(updatedAt time.Time, taskID a2a.TaskID) string {
	raw := updatedAt.UTC().Format(time.RFC3339Nano) + "_" + string(taskID)
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

func decodePageToken(token string) (time.Time, a2a.TaskID, error) {
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode page token: %w", a2a.ErrParseError)
	}
	timestampText, taskIDText, ok := strings.Cut(string(decoded), "_")
	if !ok || timestampText == "" || taskIDText == "" {
		return time.Time{}, "", fmt.Errorf("decode page token: %w", a2a.ErrParseError)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, timestampText)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode page token timestamp: %w", a2a.ErrParseError)
	}
	return updatedAt, a2a.TaskID(taskIDText), nil
}
