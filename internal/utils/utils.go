package utils

import "os"

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
