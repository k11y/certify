package utils

import (
	"os"
	"strings"
)

func IsInputPiped() bool {
	fi, _ := os.Stdin.Stat()

	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return true
	}
	return false
}

func GetFirstIndex(slice []string) string {
	if len(slice) != 0 {
		return slice[0]
	}
	return ""
}

func WrapText(input string, wrapLength int, wrapper string) string {
	trueIndex := 0
	for i := 0; i < len(input); i++ {
		if trueIndex%wrapLength == 0 && i != 0 {
			input = input[:i] + wrapper + input[i:]
			i += len(wrapper)
		}
		trueIndex += 1
	}
	return input
}

// Helper function to format hex strings with colons
func FormatHexWithColons(hexStr string) string {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	var result []string
	for i := 0; i < len(hexStr); i += 2 {
		if i+2 <= len(hexStr) {
			result = append(result, hexStr[i:i+2])
		}
	}
	return strings.Join(result, ":")
}

// Helper function to format hex blocks with proper indentation
func FormatHexBlock(hexStr string, indent int) string {
	var sb strings.Builder
	indentStr := strings.Repeat(" ", indent)

	for i := 0; i < len(hexStr); i += 30 {
		end := i + 30
		if end > len(hexStr) {
			end = len(hexStr)
		}

		line := hexStr[i:end]
		sb.WriteString(indentStr + FormatHexWithColons(line))
		if end < len(hexStr) {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
