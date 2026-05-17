package main

import (
	_ "embed"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html
var uiHTML []byte

var (
	dataDir         = envOrDefault("DATA_DIR", "/data/builds")
	alertmanagerURL = envOrDefault("ALERTMANAGER_URL", "")
	listenAddr      = envOrDefault("LISTEN_ADDR", ":8080")
	ingestSecret    = os.Getenv("INGEST_SECRET")
)

func checkIngestAuth(w http.ResponseWriter, r *http.Request) bool {
	if ingestSecret == "" {
		return true
	}
	if r.Header.Get("Authorization") != "Bearer "+ingestSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// per-auditId write mutex to prevent interleaved NDJSON lines
var writeMu sync.Map

func lockFor(auditId string) *sync.Mutex {
	v, _ := writeMu.LoadOrStore(auditId, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func main() {
	http.HandleFunc("/healthz", handleHealthz)
	http.HandleFunc("/ingest/event", handleIngestEvent)
	http.HandleFunc("/ingest/tetragon", handleIngestTetragon)
	http.HandleFunc("/ingest/http", handleIngestHttp)
	http.HandleFunc("/builds/", handleBuilds)
	http.HandleFunc("/ui", handleUI)
	http.HandleFunc("/ui/", handleUI)
	go startRetentionWorker()
	log.Printf("audit-service listening on %s, data dir %s", listenAddr, dataDir)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiHTML)
}

func handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkIngestAuth(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	auditId, _ := event["auditId"].(string)
	if auditId == "" {
		http.Error(w, "missing auditId", http.StatusBadRequest)
		return
	}

	if err := appendNDJSON(auditId, "events.ndjson", body); err != nil {
		log.Printf("ERROR writing event for %s: %v", auditId, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	if evt, _ := event["event"].(string); evt == "BUILD_END" {
		go correlate(auditId)
	}

	w.WriteHeader(http.StatusAccepted)
}

func handleIngestTetragon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkIngestAuth(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	auditId := extractTetragonAuditId(event)
	if auditId == "" {
		// exec() with no auditId in a build namespace = critical alert
		log.Printf("WARN: Tetragon exec event with no PLATFORM_AUDIT_ID: %s", string(body))
		fireAlert("exec_no_audit_id", map[string]any{
			"alertname":   "ExecWithNoAuditId",
			"severity":    "critical",
			"summary":     "exec() in build namespace with no PLATFORM_AUDIT_ID",
			"description": "A process executed without a PLATFORM_AUDIT_ID — possible pipeline bypass.",
		})
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err := appendNDJSON(auditId, "tetragon.ndjson", body); err != nil {
		log.Printf("ERROR writing tetragon event for %s: %v", auditId, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func handleIngestHttp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkIngestAuth(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	auditId, _ := event["auditId"].(string)
	if auditId == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err := appendNDJSON(auditId, "http.ndjson", body); err != nil {
		log.Printf("ERROR writing http event for %s: %v", auditId, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// handleBuilds routes GET /builds/ (list) and GET /builds/{id}/summary (detail).
func handleBuilds(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/builds/")
	if path == "" {
		handleBuildList(w, r)
		return
	}
	handleBuildSummary(w, r)
}

// handleBuildList serves GET /builds/ — returns metadata for all completed builds.
func handleBuildList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			w.Write([]byte("[]"))
			return
		}
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	type item struct {
		meta  buildMeta
		mtime time.Time
	}
	var items []item

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, _ := e.Info()
		mtime := time.Time{}
		if info != nil {
			mtime = info.ModTime()
		}
		auditId := e.Name()
		corPath := filepath.Join(dataDir, auditId, "correlated.json")
		data, err := os.ReadFile(corPath)
		if err != nil {
			// No correlated.json yet — mark as in-progress if events exist
			evPath := filepath.Join(dataDir, auditId, "events.ndjson")
			if _, serr := os.Stat(evPath); serr == nil {
				items = append(items, item{meta: buildMeta{AuditId: auditId, InProgress: true}, mtime: mtime})
			}
			continue
		}
		var meta buildMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		items = append(items, item{meta: meta, mtime: mtime})
	}

	sort.Slice(items, func(i, j int) bool { return items[i].mtime.After(items[j].mtime) })

	// Cap at 200 most recent builds
	if len(items) > 200 {
		items = items[:200]
	}

	out := make([]buildMeta, len(items))
	for i, it := range items {
		out[i] = it.meta
	}
	json.NewEncoder(w).Encode(out)
}

// handleBuildSummary serves GET /builds/{auditId}/summary — returns correlated.json.
func handleBuildSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/builds/")
	auditId := strings.TrimSuffix(path, "/summary")
	if auditId == "" || auditId == path || !strings.HasSuffix(path, "/summary") {
		http.Error(w, "invalid path — expected /builds/{auditId}/summary", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(filepath.Join(dataDir, auditId, "correlated.json"))
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found — build may not have ended yet", http.StatusNotFound)
			return
		}
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

// --- Correlation ----------------------------------------------------------------

type libraryRef struct {
	Source   string `json:"source,omitempty"`
	Library  string `json:"library,omitempty"`
	Version  string `json:"version,omitempty"`
	StepName string `json:"stepName,omitempty"`
}

type stepEvent struct {
	Event         string      `json:"event"`
	NodeId        string      `json:"nodeId"`
	StartNodeId   string      `json:"startNodeId"`
	StepName      string      `json:"stepName"`
	FunctionName  string      `json:"functionName"`
	TS            int64       `json:"ts"`
	Result        string      `json:"result"`
	DurationMs    *int64      `json:"durationMs,omitempty"`
	EnclosingIds  []string    `json:"enclosingIds,omitempty"`
	LibrarySource *libraryRef `json:"librarySource,omitempty"`
	CalledFrom    *libraryRef `json:"calledFrom,omitempty"`
}

type stepNode struct {
	NodeId       string      `json:"nodeId"`
	StepName     string      `json:"stepName"`
	FunctionName string      `json:"functionName,omitempty"`
	StartTS      int64       `json:"startTs"`
	EndTS        int64       `json:"endTs,omitempty"`
	DurationMs   *int64      `json:"durationMs,omitempty"`
	Result       string      `json:"result,omitempty"`
	Library      *libraryRef `json:"library,omitempty"`
	CalledFrom   *libraryRef `json:"calledFrom,omitempty"`
	Children     []*stepNode `json:"children,omitempty"`
}

type tetragonEvent struct {
	TS        int64  `json:"ts"`
	AuditId   string `json:"auditId"`
	EventType string `json:"event_type"`
	Binary    string `json:"binary"`
	Args      string `json:"args"`
	Pid       int    `json:"pid"`
	DestIP    string `json:"dest_ip,omitempty"`
	DestPort  int    `json:"dest_port,omitempty"`
}

type httpEvent struct {
	AuditId string `json:"auditId"`
	TS      int64  `json:"ts"`
	URL     string `json:"url"`
	Method  string `json:"method"`
	Status  int    `json:"status"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Blocked bool   `json:"blocked"`
}

type correlatedExec struct {
	TetragonEvent tetragonEvent `json:"tetragon_event"`
	MatchedStep   *stepEvent    `json:"matched_step,omitempty"`
	Anomaly       bool          `json:"anomaly"`
	AnomalyReason string        `json:"anomaly_reason,omitempty"`
}

type correlatedHttp struct {
	HttpEvent   httpEvent  `json:"http_event"`
	MatchedStep *stepEvent `json:"matched_step,omitempty"`
}

type correlationReport struct {
	AuditId             string           `json:"audit_id"`
	GeneratedAt         string           `json:"generated_at"`
	TotalSteps          int              `json:"total_steps"`
	TotalExecs          int              `json:"total_execs"`
	AnomalyCount        int              `json:"anomaly_count"`
	TotalHttpRequests   int              `json:"total_http_requests"`
	BlockedHttpRequests int              `json:"blocked_http_requests"`
	StepTree            []*stepNode      `json:"step_tree"`
	CorrelatedExecs     []correlatedExec `json:"correlated_execs"`
	CorrelatedHttp      []correlatedHttp `json:"correlated_http,omitempty"`
}

// buildMeta is a stripped-down correlationReport used for the build list endpoint.
type buildMeta struct {
	AuditId             string `json:"audit_id"`
	GeneratedAt         string `json:"generated_at,omitempty"`
	TotalSteps          int    `json:"total_steps"`
	TotalExecs          int    `json:"total_execs"`
	AnomalyCount        int    `json:"anomaly_count"`
	TotalHttpRequests   int    `json:"total_http_requests"`
	BlockedHttpRequests int    `json:"blocked_http_requests"`
	InProgress          bool   `json:"in_progress,omitempty"`
}

func correlate(auditId string) {
	// Brief pause so any in-flight POSTs from the build complete
	time.Sleep(2 * time.Second)

	buildDir := filepath.Join(dataDir, auditId)

	steps, err := readStepEvents(filepath.Join(buildDir, "events.ndjson"))
	if err != nil {
		log.Printf("WARN correlate %s: reading steps: %v", auditId, err)
	}

	tetEvents, err := readTetragonEvents(filepath.Join(buildDir, "tetragon.ndjson"))
	if err != nil {
		log.Printf("WARN correlate %s: reading tetragon events: %v", auditId, err)
	}

	httpEvents, err := readHttpEvents(filepath.Join(buildDir, "http.ndjson"))
	if err != nil {
		log.Printf("WARN correlate %s: reading http events: %v", auditId, err)
	}

	type window struct {
		step    stepEvent
		startTS int64
		endTS   int64
	}

	startsByNodeId := make(map[string]stepEvent)
	var windows []window

	for _, s := range steps {
		switch s.Event {
		case "STEP_START":
			startsByNodeId[s.NodeId] = s
		case "STEP_END":
			if start, ok := startsByNodeId[s.StartNodeId]; ok {
				windows = append(windows, window{step: start, startTS: start.TS, endTS: s.TS})
				delete(startsByNodeId, s.StartNodeId)
			}
		}
	}

	sort.Slice(windows, func(i, j int) bool { return windows[i].startTS < windows[j].startTS })

	matchStep := func(ts int64) *stepEvent {
		for i := range windows {
			if ts >= windows[i].startTS && ts <= windows[i].endTS {
				s := windows[i].step
				return &s
			}
		}
		return nil
	}

	var correlated []correlatedExec
	var anomalies []map[string]any

	for _, te := range tetEvents {
		ce := correlatedExec{TetragonEvent: te}
		ce.MatchedStep = matchStep(te.TS)
		if ce.MatchedStep == nil {
			ce.Anomaly = true
			ce.AnomalyReason = "exec() occurred outside any declared pipeline step"
			anomalies = append(anomalies, map[string]any{
				"audit_id": auditId,
				"type":     "undeclared_exec",
				"binary":   te.Binary,
				"args":     te.Args,
				"ts":       te.TS,
				"reason":   ce.AnomalyReason,
			})
			fireAlert("undeclared_exec", map[string]any{
				"alertname":   "UndeclaredExec",
				"severity":    "critical",
				"audit_id":    auditId,
				"binary":      te.Binary,
				"summary":     fmt.Sprintf("Undeclared exec() during build %s: %s", auditId, te.Binary),
				"description": "A process executed outside any declared pipeline step. Possible supply chain injection.",
			})
		}
		correlated = append(correlated, ce)
	}

	var correlHttp []correlatedHttp
	blockedCount := 0
	for _, he := range httpEvents {
		ch := correlatedHttp{HttpEvent: he}
		ch.MatchedStep = matchStep(he.TS)
		correlHttp = append(correlHttp, ch)
		if he.Blocked {
			blockedCount++
		}
	}

	report := correlationReport{
		AuditId:             auditId,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		TotalSteps:          len(windows),
		TotalExecs:          len(tetEvents),
		AnomalyCount:        len(anomalies),
		TotalHttpRequests:   len(httpEvents),
		BlockedHttpRequests: blockedCount,
		StepTree:            buildStepTree(steps),
		CorrelatedExecs:     correlated,
		CorrelatedHttp:      correlHttp,
	}

	writeJSON(filepath.Join(buildDir, "correlated.json"), report)
	if len(anomalies) > 0 {
		writeJSON(filepath.Join(buildDir, "anomalies.json"), anomalies)
	}

	log.Printf("correlation complete %s: steps=%d execs=%d http=%d blocked=%d anomalies=%d",
		auditId, report.TotalSteps, report.TotalExecs, report.TotalHttpRequests, blockedCount, report.AnomalyCount)
}

// --- Step tree ------------------------------------------------------------------

func buildStepTree(steps []stepEvent) []*stepNode {
	nodesByStart := make(map[string]*stepNode)

	for _, s := range steps {
		if s.Event != "STEP_START" {
			continue
		}
		n := &stepNode{
			NodeId:       s.NodeId,
			StepName:     s.StepName,
			FunctionName: s.FunctionName,
			StartTS:      s.TS,
			Library:      s.LibrarySource,
			CalledFrom:   s.CalledFrom,
		}
		nodesByStart[s.NodeId] = n
	}

	for _, s := range steps {
		if s.Event != "STEP_END" || s.StartNodeId == "" {
			continue
		}
		if n, ok := nodesByStart[s.StartNodeId]; ok {
			n.EndTS = s.TS
			n.Result = s.Result
			if s.DurationMs != nil {
				n.DurationMs = s.DurationMs
			}
		}
	}

	childOf := make(map[string]string)
	for _, s := range steps {
		if s.Event != "STEP_START" || len(s.EnclosingIds) == 0 {
			continue
		}
		for _, encId := range s.EnclosingIds {
			if _, ok := nodesByStart[encId]; ok {
				childOf[s.NodeId] = encId
				break
			}
		}
	}

	for childId, parentId := range childOf {
		parent := nodesByStart[parentId]
		child := nodesByStart[childId]
		if parent != nil && child != nil {
			parent.Children = append(parent.Children, child)
		}
	}

	var roots []*stepNode
	for nodeId, n := range nodesByStart {
		if _, hasParent := childOf[nodeId]; !hasParent {
			roots = append(roots, n)
		}
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].StartTS < roots[j].StartTS })
	sortChildren(roots)

	return roots
}

func sortChildren(nodes []*stepNode) {
	for _, n := range nodes {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].StartTS < n.Children[j].StartTS })
		sortChildren(n.Children)
	}
}

// --- Retention ------------------------------------------------------------------

func startRetentionWorker() {
	retentionDays := 30
	if v := os.Getenv("RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d >= 0 {
			retentionDays = d
		}
	}
	time.Sleep(time.Second)
	runRetention(retentionDays)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		runRetention(retentionDays)
	}
}

func runRetention(days int) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("retention: ReadDir %s: %v", dataDir, err)
		}
		return
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dataDir, e.Name())
			if err := os.RemoveAll(path); err != nil {
				log.Printf("retention: remove %s: %v", path, err)
			} else {
				removed++
			}
		}
	}
	if removed > 0 {
		log.Printf("retention: removed %d build dir(s) older than %d days", removed, days)
	}
}

// --- File helpers ---------------------------------------------------------------

func appendNDJSON(auditId, filename string, data []byte) error {
	mu := lockFor(auditId)
	mu.Lock()
	defer mu.Unlock()

	dir := filepath.Join(dataDir, auditId)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", strings.TrimSpace(string(data)))
	return err
}

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("ERROR marshaling %s: %v", path, err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("ERROR writing %s: %v", path, err)
	}
}

func readStepEvents(path string) ([]stepEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []stepEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var e stepEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.LibrarySource != nil && e.LibrarySource.Source != "library" {
			e.LibrarySource = nil
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}

func readTetragonEvents(path string) ([]tetragonEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []tetragonEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e tetragonEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}

func readHttpEvents(path string) ([]httpEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []httpEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e httpEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, scanner.Err()
}

// --- Tetragon helpers -----------------------------------------------------------

func extractTetragonAuditId(event map[string]any) string {
	if id, ok := event["auditId"].(string); ok && id != "" {
		return id
	}
	if proc, ok := event["process"].(map[string]any); ok {
		if env, ok := proc["arguments_env"].(string); ok {
			for _, kv := range strings.Split(env, "\x00") {
				if strings.HasPrefix(kv, "PLATFORM_AUDIT_ID=") {
					return strings.TrimPrefix(kv, "PLATFORM_AUDIT_ID=")
				}
			}
		}
	}
	return ""
}

// --- Alertmanager integration ---------------------------------------------------

type amAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
}

func fireAlert(alertName string, fields map[string]any) {
	labels := map[string]string{
		"alertname": alertName,
		"severity":  "critical",
	}
	annotations := map[string]string{}

	for k, v := range fields {
		s := fmt.Sprintf("%v", v)
		switch k {
		case "alertname", "severity":
			labels[k] = s
		case "summary", "description":
			annotations[k] = s
		default:
			labels[k] = s
		}
	}

	alert := []amAlert{{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    time.Now().UTC().Format(time.RFC3339),
	}}

	if alertmanagerURL == "" {
		log.Printf("ALERT %s: %v", alertName, fields)
		return
	}

	body, _ := json.Marshal(alert)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(alertmanagerURL+"/api/v2/alerts", "application/json",
		strings.NewReader(string(body)))
	if err != nil {
		log.Printf("ALERT fire failed (%s): %v — alert: %v", alertName, err, fields)
		return
	}
	resp.Body.Close()
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
