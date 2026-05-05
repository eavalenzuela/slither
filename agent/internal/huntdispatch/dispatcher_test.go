package huntdispatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/extensions"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

type fakeProvider struct {
	mu    sync.Mutex
	calls []*pb.LiveQueryRequest
	rows  []*pb.ExtensionToAgent
	err   error
	done  bool
}

func (f *fakeProvider) DispatchLiveQuery(ctx context.Context, req *pb.LiveQueryRequest) (<-chan *pb.ExtensionToAgent, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	rows := f.rows
	err := f.err
	done := f.done
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	ch := make(chan *pb.ExtensionToAgent, len(rows)+1)
	for _, r := range rows {
		ch <- r
	}
	if done {
		ch <- &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_LiveQueryComplete{
				LiveQueryComplete: &pb.LiveQueryComplete{
					QueryId:  req.QueryId,
					RowCount: uint64(len(rows)),
				},
			},
		}
	}
	close(ch)
	return ch, nil
}

func TestDispatcher_NoExtensionMapsToTerminalError(t *testing.T) {
	provider := &fakeProvider{err: extensions.ErrNoLiveQueryProvider}
	results := make(chan *pb.HuntResult, 8)
	d := New(provider, results)
	d.Submit(context.Background(), &pb.HuntQuery{
		ControlId: "00000000-0000-0000-0000-000000000001",
		Query:     "SELECT 1",
		MaxRows:   100,
	})
	select {
	case hr := <-results:
		complete := hr.GetComplete()
		if complete == nil {
			t.Fatal("expected complete on terminal error")
		}
		if !strings.Contains(complete.Error, "no extension declares live_query_respond") {
			t.Errorf("error=%q", complete.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not emit terminal HuntResult")
	}
}

func TestDispatcher_RowsAndCompleteFlowThrough(t *testing.T) {
	provider := &fakeProvider{
		rows: []*pb.ExtensionToAgent{
			{Payload: &pb.ExtensionToAgent_LiveQueryRow{LiveQueryRow: &pb.LiveQueryRow{
				QueryId: "q1", Columns: []string{"k"}, Values: []string{"v"},
			}}},
			{Payload: &pb.ExtensionToAgent_LiveQueryRow{LiveQueryRow: &pb.LiveQueryRow{
				QueryId: "q1", Columns: []string{"k"}, Values: []string{"v2"},
			}}},
		},
		done: true,
	}
	results := make(chan *pb.HuntResult, 16)
	d := New(provider, results)
	d.Submit(context.Background(), &pb.HuntQuery{
		ControlId:   "q1",
		Query:       "SELECT k FROM t",
		MaxRows:     100,
		TimeoutSecs: 5,
	})

	var got []*pb.HuntResult
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case hr := <-results:
			got = append(got, hr)
			if hr.GetComplete() != nil {
				goto done
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
done:
	if len(got) == 0 {
		t.Fatal("no HuntResult emitted")
	}
	last := got[len(got)-1]
	if last.GetComplete() == nil {
		t.Errorf("last message must be complete")
	}
	if last.GetComplete().GetError() != "" {
		t.Errorf("expected no error, got %q", last.GetComplete().GetError())
	}
	if last.GetComplete().GetRowCount() != 2 {
		t.Errorf("row_count=%d, want 2", last.GetComplete().GetRowCount())
	}
	totalRows := 0
	for _, hr := range got {
		totalRows += len(hr.GetRows())
	}
	if totalRows != 2 {
		t.Errorf("rows total=%d, want 2", totalRows)
	}
}

func TestDispatcher_RowCapTruncates(t *testing.T) {
	rows := make([]*pb.ExtensionToAgent, 0, 5)
	for i := 0; i < 5; i++ {
		rows = append(rows, &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_LiveQueryRow{
				LiveQueryRow: &pb.LiveQueryRow{
					QueryId: "qcap", Columns: []string{"k"}, Values: []string{"v"},
				},
			},
		})
	}
	provider := &fakeProvider{rows: rows, done: true}
	results := make(chan *pb.HuntResult, 16)
	d := New(provider, results)
	d.Submit(context.Background(), &pb.HuntQuery{
		ControlId:   "qcap",
		Query:       "SELECT 1",
		MaxRows:     2,
		TimeoutSecs: 5,
	})

	deadline := time.Now().Add(time.Second)
	totalRows := 0
	var capMsg string
	for time.Now().Before(deadline) {
		select {
		case hr := <-results:
			totalRows += len(hr.GetRows())
			if c := hr.GetComplete(); c != nil {
				capMsg = c.Error
				if totalRows != 2 {
					t.Errorf("forwarded row count=%d, want 2 (cap)", totalRows)
				}
				if !strings.Contains(capMsg, "row cap exceeded") {
					t.Errorf("expected cap-truncation marker, got %q", capMsg)
				}
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("never received complete")
}

type erringProvider struct{}

func (erringProvider) DispatchLiveQuery(ctx context.Context, req *pb.LiveQueryRequest) (<-chan *pb.ExtensionToAgent, error) {
	return nil, errors.New("transport down")
}

func TestDispatcher_GenericProviderErrorForwarded(t *testing.T) {
	results := make(chan *pb.HuntResult, 4)
	d := New(erringProvider{}, results)
	d.Submit(context.Background(), &pb.HuntQuery{ControlId: "q1", Query: "x"})
	select {
	case hr := <-results:
		if !strings.Contains(hr.GetComplete().GetError(), "transport down") {
			t.Errorf("error=%q", hr.GetComplete().GetError())
		}
	case <-time.After(time.Second):
		t.Fatal("no terminal HuntResult")
	}
}
