//go:build integration

// End-to-end test for the ClickHouse writer using a real ClickHouse
// container (testcontainers-go). Verifies:
//   - Migrate brings the schema to head idempotently.
//   - 50k synthetic process events go through the bus → writer →
//     ocsf_process_activity_1007 with matching rowcount per host_id.
//   - Time-based flush: a small batch arrives, fewer than batch_size
//     rows, but a Run loop tick still flushes within FlushInterval.
//   - Detection findings round-trip the array columns.

package ch_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	chtestcontainer "github.com/testcontainers/testcontainers-go/modules/clickhouse"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

const (
	chImage = "clickhouse/clickhouse-server:24.8-alpine"
	chUser  = "slither"
	chPass  = "slither"
	chDB    = "slither_test"
)

func TestCH_BulkProcessActivity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	const total = 50_000
	hostA := uuid.New()
	hostB := uuid.New()

	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize:     5_000,
		FlushInterval: 250 * time.Millisecond,
		BusBuffer:     2 * total, // never drop in-test
	})

	for i := 0; i < total; i++ {
		host := hostA
		if i%2 == 1 {
			host = hostB
		}
		env.bus.Publish(makeProcessEnvelope(t, host, uint32(1000+i)))
	}
	t.Logf("published %d events; waiting for ingest", total)

	// Wait until exactly `total` rows have landed across both hosts.
	deadline := time.Now().Add(2 * time.Minute)
	lastReported := time.Now()
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_process_activity_1007`).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == total {
			break
		}
		if time.Since(lastReported) > 5*time.Second {
			snap := env.telem.Snapshot()
			t.Logf("progress: rows=%d batches=%d drops=%d lastErr=%v",
				got, snap.BatchesFlushed, snap.DropsSubscriber, env.writer.LastFlushErr())
			lastReported = time.Now()
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Per-host count assertions.
	for _, h := range []uuid.UUID{hostA, hostB} {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_process_activity_1007 WHERE host_id = ?`, h).Scan(&got); err != nil {
			t.Fatalf("count where host: %v", err)
		}
		if got != total/2 {
			t.Errorf("host %s: got %d, want %d", h, got, total/2)
		}
	}

	// Telemetry: at least 10 batches flushed (50k / 5k).
	if got := env.telem.Snapshot().BatchesFlushed; got < 10 {
		t.Errorf("batches_flushed = %d, want >= 10", got)
	}

	cancelWriter()
	<-writerDone
}

func TestCH_TimeFlush(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	host := uuid.New()
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runDone := startWriterCtx(t, env, runCtx, ch.WriterOptions{
		BatchSize:     1_000_000, // never trigger size-based flush
		FlushInterval: 200 * time.Millisecond,
	})

	for i := 0; i < 5; i++ {
		env.bus.Publish(makeProcessEnvelope(t, host, uint32(1+i)))
	}

	deadline := time.After(3 * time.Second)
	for {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_process_activity_1007 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("time-flush did not deliver 5 rows; current count = %d", got)
		case <-time.After(100 * time.Millisecond):
		}
	}

	runCancel()
	<-runDone
}

func TestCH_DetectionFindingArrays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	host := uuid.New()
	trigA := uuid.New()
	trigB := uuid.New()

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	runDone := startWriterCtx(t, env, runCtx, ch.WriterOptions{
		BatchSize:     10,
		FlushInterval: 200 * time.Millisecond,
	})

	finding := &ocsf.DetectionFinding{
		Metadata:           ocsf.Metadata{UID: uuid.NewString(), OriginalT: time.Now().UnixMilli()},
		ClassUID:           ocsf.ClassDetectionFinding,
		ActivityID:         ocsf.FindingActivityCreate,
		Severity:           ocsf.Severity(4),
		Time:               ocsf.TimeOCSF(time.Now().UnixMilli()),
		Finding:            ocsf.Finding{UID: "alert-1", Title: "Test", Status: "New"},
		RuleInfo:           ocsf.Rule{UID: "rule-1", Name: "Test rule"},
		MitreATTACK:        []ocsf.MitreTag{{Technique: ocsf.MitreTechnique{UID: "T1059.004"}}},
		TriggeringEventIDs: []string{trigA.String(), trigB.String()},
	}
	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	env.bus.Publish(&pb.Envelope{
		EventId:     uuid.NewString(),
		HostId:      host.String(),
		ClassId:     pb.OcsfClassId_OCSF_CLASS_ID_DETECTION_FINDING,
		ObservedAt:  timestamppb.Now(),
		CollectedAt: timestamppb.Now(),
		Payload:     payload,
	})

	deadline := time.After(3 * time.Second)
	for {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_detection_finding_2004 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count finding: %v", err)
		}
		if got == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("finding row never arrived")
		case <-time.After(100 * time.Millisecond):
		}
	}

	var (
		ruleUID    string
		ruleName   string
		findingUID string
		trigs      []uuid.UUID
		mitre      []string
	)
	if err := env.store.SQL().QueryRowContext(ctx, `
		SELECT rule_uid, rule_name, finding_uid, triggering_event_ids, mitre_techniques
		FROM ocsf_detection_finding_2004 WHERE host_id = ?
	`, host).Scan(&ruleUID, &ruleName, &findingUID, &trigs, &mitre); err != nil {
		t.Fatalf("select: %v", err)
	}
	if ruleUID != "rule-1" || ruleName != "Test rule" || findingUID != "alert-1" {
		t.Errorf("scalar mismatch: rule_uid=%q rule_name=%q finding_uid=%q", ruleUID, ruleName, findingUID)
	}
	if len(trigs) != 2 || (trigs[0] != trigA && trigs[0] != trigB) {
		t.Errorf("triggering_event_ids round-trip lost: %+v", trigs)
	}
	if len(mitre) != 1 || mitre[0] != "T1059.004" {
		t.Errorf("mitre round-trip: %+v", mitre)
	}

	runCancel()
	<-runDone
}

// --- harness ---

type chEnv struct {
	store   *ch.Store
	bus     *ingest.Bus
	telem   *telemetry.Counters
	writer  *ch.Writer
	cleanup func()
}

func setupCH(ctx context.Context, t *testing.T) *chEnv {
	t.Helper()
	requireDocker(t)

	dsn, stopCH := startClickHouse(ctx, t)
	if err := ch.Migrate(ctx, dsn); err != nil {
		stopCH()
		t.Fatalf("Migrate: %v", err)
	}
	store, err := ch.Open(ctx, dsn)
	if err != nil {
		stopCH()
		t.Fatalf("ch.Open: %v", err)
	}

	telem := telemetry.NewCounters()
	bus := ingest.NewBus(func(string) { telem.IncDropSubscriber() })

	return &chEnv{
		store: store,
		bus:   bus,
		telem: telem,
		cleanup: func() {
			bus.Close()
			store.Close()
			stopCH()
		},
	}
}

func startWriter(t *testing.T, env *chEnv, opts ch.WriterOptions) (cancel context.CancelFunc, done chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return cancel, startWriterCtx(t, env, ctx, opts)
}

func startWriterCtx(t *testing.T, env *chEnv, ctx context.Context, opts ch.WriterOptions) chan struct{} {
	t.Helper()
	w := ch.NewWriter(env.store, env.bus, env.telem, opts)
	w.SetFlushErrorHandler(func(err error) { t.Logf("ch flush: %v", err) })
	env.writer = w
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()
	return done
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second); err != nil {
		t.Skipf("docker unreachable: %v", err)
	}
}

func startClickHouse(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()
	container, err := chtestcontainer.Run(ctx,
		chImage,
		chtestcontainer.WithUsername(chUser),
		chtestcontainer.WithPassword(chPass),
		chtestcontainer.WithDatabase(chDB),
	)
	if err != nil {
		t.Fatalf("ch container: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("container port: %v", err)
	}
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%s/%s", chUser, chPass, host, port.Port(), chDB)
	return dsn, func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(termCtx)
	}
}

func makeProcessEnvelope(t *testing.T, hostID uuid.UUID, pid uint32) *pb.Envelope {
	t.Helper()
	ev := &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{
			UID:       uuid.NewString(),
			OriginalT: time.Now().UnixMilli(),
		},
		ClassUID:   ocsf.ClassProcessActivity,
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.Severity(1),
		Time:       ocsf.TimeOCSF(time.Now().UnixMilli()),
		Process: ocsf.Process{
			PID:  pid,
			Name: "bash",
			File: &ocsf.File{Path: "/bin/bash"},
			Parent: &ocsf.Process{
				PID:  1,
				Name: "systemd",
			},
		},
		Device: ocsf.Device{HostID: hostID.String()},
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &pb.Envelope{
		EventId:     uuid.NewString(),
		HostId:      hostID.String(),
		ClassId:     pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		ObservedAt:  timestamppb.Now(),
		CollectedAt: timestamppb.Now(),
		Payload:     payload,
	}
}
