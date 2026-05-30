package codec_test

import (
	"strings"
	"testing"

	"github.com/maksym-mishchenko/mcpgate/internal/codec"
)

func FuzzRead(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}` + "\n")
	f.Add(`[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]` + "\n")
	f.Add("")
	f.Add("\n\n\n")

	f.Fuzz(func(t *testing.T, s string) {
		c := codec.New(strings.NewReader(s))
		for {
			_, err := c.Read()
			if err != nil {
				return
			}
		}
	})
}
