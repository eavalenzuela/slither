package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOsqueryiClient_QueryRows_ParsesJSON(t *testing.T) {
	client := &OsqueryiClient{
		BinaryPath: "osqueryi-fake",
		SocketPath: "/var/osquery/osquery.em",
		runCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name != "osqueryi-fake" {
				t.Errorf("expected osqueryi-fake, got %q", name)
			}
			// Last arg is the SQL.
			if !strings.HasPrefix(args[len(args)-1], "SELECT") {
				t.Errorf("expected SQL last, got %q", args[len(args)-1])
			}
			return []byte(`[{"pid":"100","name":"sshd"},{"pid":"101","name":"bash"}]`), nil
		},
	}
	rows, err := client.QueryRows(context.Background(), "SELECT * FROM processes")
	if err != nil {
		t.Fatalf("QueryRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0]["pid"] != "100" || rows[0]["name"] != "sshd" {
		t.Errorf("row 0 wrong: %v", rows[0])
	}
}

func TestOsqueryiClient_QueryRows_EmptyResult(t *testing.T) {
	client := &OsqueryiClient{
		BinaryPath: "osqueryi",
		runCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("[]"), nil
		},
	}
	rows, err := client.QueryRows(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("QueryRows: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected empty rows, got %d", len(rows))
	}
}

func TestOsqueryiClient_QueryRows_BinaryMissingMapsToUnavailable(t *testing.T) {
	client := &OsqueryiClient{
		BinaryPath: "osqueryi-does-not-exist",
		runCmd:     defaultRunCmd,
	}
	_, err := client.QueryRows(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatal("expected error from missing binary")
	}
	if !errors.Is(err, ErrClientUnavailable) {
		t.Errorf("expected ErrClientUnavailable, got %v", err)
	}
}

func TestOsqueryiClient_QueryRows_RejectsEmptySQL(t *testing.T) {
	client := NewOsqueryiClient("", "")
	_, err := client.QueryRows(context.Background(), "")
	if err == nil {
		t.Fatal("expected error from empty sql")
	}
}

func TestOsqueryiClient_QueryRows_OmitsConnectWhenSocketEmpty(t *testing.T) {
	var capturedArgs []string
	client := &OsqueryiClient{
		BinaryPath: "osqueryi",
		SocketPath: "",
		runCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			capturedArgs = args
			return []byte("[]"), nil
		},
	}
	if _, err := client.QueryRows(context.Background(), "SELECT 1"); err != nil {
		t.Fatalf("QueryRows: %v", err)
	}
	for _, a := range capturedArgs {
		if a == "--connect" {
			t.Errorf("--connect must not appear when SocketPath is empty: %v", capturedArgs)
		}
	}
}
