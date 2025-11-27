package workflow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf16"
)

// BOFArgument represents a typed argument for BOF execution
type BOFArgument struct {
	Type  string      `yaml:"type"`
	Value interface{} `yaml:"value"`
}

// PackBOFArguments packs typed arguments into binary format for BOF execution
// Format verified against Cobalt Strike 4.x bof_pack() implementation
//
// Key format details:
// - string (z): [length:4 BE][char1:1][char2:1]...[null:1]
// - wstring (Z): [length:4 BE][utf16le_char1:2][utf16le_char2:2]...[null:2]
// - int (i): [int:4 BE] (no length prefix)
// - short (s): [short:2 BE] (no length prefix)
// - binary (b): [length:4 BE][data...]
//
// Each variable-length argument (string/wstring/binary) has its own 4-byte BIG-ENDIAN
// length prefix immediately before the data. Fixed-size types (int/short) have no prefix.
//
// Format: [arg1_with_prefix_if_varlen][arg2_with_prefix_if_varlen]...
func PackBOFArguments(args []BOFArgument) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var buff []byte

	for _, arg := range args {
		var data []byte
		var err error

		switch arg.Type {
		case "binary", "b":
			data, err = packBinaryWithPrefix(arg.Value)
		case "int", "i":
			data, err = packInt(arg.Value)
		case "short", "s":
			data, err = packShort(arg.Value)
		case "string", "z":
			data, err = packStringWithPrefix(arg.Value)
		case "wstring", "Z":
			data, err = packWideStringWithPrefix(arg.Value)
		default:
			return nil, fmt.Errorf("unsupported argument type: %s", arg.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to pack %s argument: %w", arg.Type, err)
		}

		buff = append(buff, data...)
	}

	return buff, nil
}

// packBinaryWithPrefix packs binary data with 4-byte BE length prefix
// Format: [length:4 BE][data...]
func packBinaryWithPrefix(value interface{}) ([]byte, error) {
	var hexString string

	switch val := value.(type) {
	case string:
		hexString = val
	case []byte:
		hexString = hex.EncodeToString(val)
	default:
		return nil, fmt.Errorf("invalid type for binary: %T", value)
	}

	hexData, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}

	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, uint32(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

// packInt packs a 32-bit integer in BIG-ENDIAN format (no length prefix)
// Format: [int:4 BE]
func packInt(value interface{}) ([]byte, error) {
	var i uint32

	switch val := value.(type) {
	case int:
		i = uint32(val)
	case int32:
		i = uint32(val)
	case uint32:
		i = val
	case float64:
		i = uint32(val)
	case string:
		parsed, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, err
		}
		i = uint32(parsed)
	default:
		return nil, fmt.Errorf("invalid type for int: %T", value)
	}

	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, i)
	return buff, nil
}

// packShort packs a 16-bit short in BIG-ENDIAN format (no length prefix)
// Format: [short:2 BE]
func packShort(value interface{}) ([]byte, error) {
	var i uint16

	switch val := value.(type) {
	case int:
		i = uint16(val)
	case int16:
		i = uint16(val)
	case uint16:
		i = val
	case float64:
		i = uint16(val)
	case string:
		parsed, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return nil, err
		}
		i = uint16(parsed)
	default:
		return nil, fmt.Errorf("invalid type for short: %T", value)
	}

	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, i)
	return buff, nil
}

// packStringWithPrefix packs an ASCII string with 4-byte BE length prefix and null terminator
// Format: [length:4 BE][char1:1][char2:1]...[null:1]
// Note: Length includes the null terminator
func packStringWithPrefix(value interface{}) ([]byte, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for string: %T", value)
	}

	// String data with null terminator
	strData := append([]byte(str), 0)

	// Prepend 4-byte BE length (including null terminator)
	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, uint32(len(strData)))
	buff = append(buff, strData...)

	return buff, nil
}

// packWideStringWithPrefix packs a UTF-16LE wide string with 4-byte BE length prefix and null terminator
// Format: [byte_length:4 BE][utf16le_char1:2][utf16le_char2:2]...[null:2]
// Note: Length is in bytes (including the 2-byte null terminator)
func packWideStringWithPrefix(value interface{}) ([]byte, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for wstring: %T", value)
	}

	// Convert to UTF-16
	runes := []rune(str)
	utf16Encoded := utf16.Encode(runes)

	// Allocate buffer for UTF-16LE data + null terminator
	wstrData := make([]byte, (len(utf16Encoded)+1)*2)

	// Write UTF-16LE bytes
	for i, utf16Char := range utf16Encoded {
		binary.LittleEndian.PutUint16(wstrData[i*2:], utf16Char)
	}

	// Add UTF-16LE null terminator
	binary.LittleEndian.PutUint16(wstrData[len(utf16Encoded)*2:], 0)

	// Prepend 4-byte BE length (in bytes, including null terminator)
	buff := make([]byte, 4)
	binary.BigEndian.PutUint32(buff, uint32(len(wstrData)))
	buff = append(buff, wstrData...)

	return buff, nil
}
