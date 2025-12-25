package ingest

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// ForwardMessageType represents the type of Forward protocol message
type ForwardMessageType int

const (
	MessageMode ForwardMessageType = iota
	ForwardMode
	PackedForwardMode
	CompressedPackedForwardMode
)

// ForwardMessage represents a single message in Message mode
// Format: [tag, time, record]
type ForwardMessage struct {
	Tag     string
	Time    interface{} // int64 (Unix timestamp) or EventTime
	Record  map[string]interface{}
	Options map[string]interface{} // Optional options map
}

// ForwardBatch represents a batch of messages in Forward mode
// Format: [tag, [[time, record], [time, record], ...]]
type ForwardBatch struct {
	Tag     string
	Entries []ForwardEntry
	Options map[string]interface{} // Optional options map
}

// ForwardEntry represents a single entry in a batch
type ForwardEntry struct {
	Time   interface{}
	Record map[string]interface{}
}

// PackedForward represents a packed forward message
// Format: [tag, binary]
type PackedForward struct {
	Tag     string
	Entries []byte                 // MessagePack stream of entries
	Options map[string]interface{} // Optional options with "compressed" flag
}

// EventTime represents Fluentd EventTime format (seconds + nanoseconds)
type EventTime struct {
	Seconds     uint32
	Nanoseconds uint32
}

// ToTime converts EventTime to time.Time
func (et EventTime) ToTime() time.Time {
	return time.Unix(int64(et.Seconds), int64(et.Nanoseconds))
}

// ParseForwardMessage parses a MessagePack-encoded Forward protocol message
func ParseForwardMessage(data []byte) (*ForwardMessage, *ForwardBatch, *PackedForward, ForwardMessageType, error) {
	dec := msgpack.NewDecoder(bytes.NewReader(data))

	// First, decode as array to determine length
	arrayLen, err := dec.DecodeArrayLen()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to decode array length: %w", err)
	}

	if arrayLen < 2 || arrayLen > 4 {
		return nil, nil, nil, 0, fmt.Errorf("invalid array length: %d (expected 2-4)", arrayLen)
	}

	// Decode tag (first element, always string)
	tag, err := dec.DecodeString()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to decode tag: %w", err)
	}

	// Decode the second element to determine message type
	secondElement, err := dec.DecodeInterface()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to decode second element: %w", err)
	}

	switch v := secondElement.(type) {
	case int64, uint64, int, uint, EventTime:
		// Message mode: [tag, time, record]
		// timeVal already decoded, dec is now at record position
		msg, err := parseMessageMode(tag, v, dec, arrayLen)
		return msg, nil, nil, MessageMode, err

	case []interface{}:
		// Forward mode: [tag, [[time, record], ...]]
		// entries already decoded, dec is now at options position (if present)
		batch, err := parseForwardMode(tag, v, arrayLen, dec)
		return nil, batch, nil, ForwardMode, err

	case []byte:
		// Packed or CompressedPacked mode: [tag, binary]
		// binary data already decoded, dec is now at options position (if present)
		packed, msgType, err := parsePackedMode(tag, v, arrayLen, dec)
		return nil, nil, packed, msgType, err

	default:
		return nil, nil, nil, 0, fmt.Errorf("unknown second element type: %T", v)
	}
}

// parseMessageMode parses Message mode: [tag, time, record] or [tag, time, record, options]
func parseMessageMode(tag string, timeVal interface{}, dec *msgpack.Decoder, arrayLen int) (*ForwardMessage, error) {
	// Convert time to int64
	timestamp, err := convertToUnixTime(timeVal)
	if err != nil {
		return nil, fmt.Errorf("failed to convert time: %w", err)
	}

	// Decode record (map)
	record, err := dec.DecodeMap()
	if err != nil {
		return nil, fmt.Errorf("failed to decode record: %w", err)
	}

	msg := &ForwardMessage{
		Tag:    tag,
		Time:   timestamp,
		Record: record,
	}

	// Check if there's an options map (4th element)
	// We need to check if there are more elements
	// This is a bit tricky with msgpack decoder, so we'll just try to decode
	// If it fails, that's fine - no options
	options, err := dec.DecodeMap()
	if err == nil {
		msg.Options = options
	}

	return msg, nil
}

// parseForwardMode parses Forward mode: [tag, [[time, record], ...]]
func parseForwardMode(tag string, entries []interface{}, arrayLen int, dec *msgpack.Decoder) (*ForwardBatch, error) {
	batch := &ForwardBatch{
		Tag:     tag,
		Entries: make([]ForwardEntry, 0, len(entries)),
	}

	for i, entry := range entries {
		entryArray, ok := entry.([]interface{})
		if !ok || len(entryArray) < 2 {
			return nil, fmt.Errorf("invalid entry at index %d: not an array or too short", i)
		}

		// First element is time
		timestamp, err := convertToUnixTime(entryArray[0])
		if err != nil {
			return nil, fmt.Errorf("failed to convert time at entry %d: %w", i, err)
		}

		// Second element is record
		record, ok := entryArray[1].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid record at entry %d: not a map", i)
		}

		batch.Entries = append(batch.Entries, ForwardEntry{
			Time:   timestamp,
			Record: record,
		})
	}

	return batch, nil
}

// parsePackedMode parses PackedForward or CompressedPackedForward mode
func parsePackedMode(tag string, binaryData []byte, arrayLen int, dec *msgpack.Decoder) (*PackedForward, ForwardMessageType, error) {
	packed := &PackedForward{
		Tag:     tag,
		Entries: binaryData,
	}

	msgType := PackedForwardMode

	// Check if there's an options map (3rd element)
	if arrayLen >= 3 {
		options, err := dec.DecodeMap()
		if err == nil {
			packed.Options = options

			// Check if compressed flag is set
			if compressed, ok := options["compressed"].(string); ok && compressed == "gzip" {
				msgType = CompressedPackedForwardMode
			}
		}
	}

	return packed, msgType, nil
}

// UnpackPackedForward unpacks a PackedForward message into individual entries
func UnpackPackedForward(packed *PackedForward, compressed bool) ([]ForwardEntry, error) {
	var reader io.Reader = bytes.NewReader(packed.Entries)

	// Decompress if needed
	if compressed {
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() {
			if err := gzReader.Close(); err != nil {
				// Log error but don't fail the operation as data is already read
				// Note: In production, consider using a logger here
			}
		}()
		reader = gzReader
	}

	// Decode entries as a stream of [time, record] arrays
	dec := msgpack.NewDecoder(reader)
	entries := make([]ForwardEntry, 0)

	for {
		// Try to decode an entry array
		arrayLen, err := dec.DecodeArrayLen()
		if err == io.EOF {
			break // End of stream
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode entry array length: %w", err)
		}

		if arrayLen != 2 {
			return nil, fmt.Errorf("invalid entry array length: %d (expected 2)", arrayLen)
		}

		// Decode time
		timeVal, err := dec.DecodeInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to decode time: %w", err)
		}

		timestamp, err := convertToUnixTime(timeVal)
		if err != nil {
			return nil, fmt.Errorf("failed to convert time: %w", err)
		}

		// Decode record
		record, err := dec.DecodeMap()
		if err != nil {
			return nil, fmt.Errorf("failed to decode record: %w", err)
		}

		entries = append(entries, ForwardEntry{
			Time:   timestamp,
			Record: record,
		})
	}

	return entries, nil
}

// convertToUnixTime converts various time formats to Unix timestamp (int64)
func convertToUnixTime(timeVal interface{}) (int64, error) {
	switch v := timeVal.(type) {
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case int:
		return int64(v), nil
	case uint:
		return int64(v), nil
	case EventTime:
		return v.ToTime().Unix(), nil
	case map[string]interface{}:
		// EventTime extension type (might be decoded as map)
		if sec, ok := v["seconds"].(uint32); ok {
			if nsec, ok := v["nanoseconds"].(uint32); ok {
				et := EventTime{Seconds: sec, Nanoseconds: nsec}
				return et.ToTime().Unix(), nil
			}
		}
		return 0, fmt.Errorf("invalid EventTime map structure")
	default:
		return 0, fmt.Errorf("unsupported time type: %T", timeVal)
	}
}

// Authentication support for Fluentd Forward protocol

// GenerateNonce generates a random nonce for authentication
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// ComputeHMAC computes HMAC-SHA256 for authentication
func ComputeHMAC(sharedKey string, salt, nonce []byte) string {
	h := hmac.New(sha256.New, []byte(sharedKey))
	h.Write(salt)
	h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateHMAC validates HMAC for authentication
func ValidateHMAC(sharedKey string, salt, nonce []byte, providedHMAC string) bool {
	expectedHMAC := ComputeHMAC(sharedKey, salt, nonce)
	return hmac.Equal([]byte(expectedHMAC), []byte(providedHMAC))
}

// ACK support for guaranteed delivery

// ACKResponse represents an acknowledgment response
type ACKResponse struct {
	Ack string `msgpack:"ack"`
}

// EncodeACK encodes an ACK response
func EncodeACK(chunkID string) ([]byte, error) {
	ack := ACKResponse{Ack: chunkID}
	return msgpack.Marshal(ack)
}

// DecodeACK decodes an ACK response
func DecodeACK(data []byte) (string, error) {
	var ack ACKResponse
	if err := msgpack.Unmarshal(data, &ack); err != nil {
		return "", fmt.Errorf("failed to unmarshal ACK: %w", err)
	}
	return ack.Ack, nil
}

// Helper functions

// ValidateRecord validates a record map for security
func ValidateRecord(record map[string]interface{}, maxFields, maxFieldSize int) error {
	if len(record) > maxFields {
		return fmt.Errorf("record has too many fields: %d (max %d)", len(record), maxFields)
	}

	for key, value := range record {
		// Validate key
		if len(key) > 256 {
			return fmt.Errorf("field name too long: %d bytes", len(key))
		}

		// Validate value size if it's a string
		if str, ok := value.(string); ok {
			if len(str) > maxFieldSize {
				return fmt.Errorf("field '%s' value too large: %d bytes (max %d)", key, len(str), maxFieldSize)
			}
		}
	}

	return nil
}

// SanitizeRecord sanitizes a record for security
func SanitizeRecord(record map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})

	for key, value := range record {
		// Remove null bytes from strings
		if str, ok := value.(string); ok {
			sanitized[key] = bytes.ReplaceAll([]byte(str), []byte{0}, []byte{})
		} else {
			sanitized[key] = value
		}
	}

	return sanitized
}
