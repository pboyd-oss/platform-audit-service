package main

import (
	_ "embed"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var internalCIDRs = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

func isExternalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range internalCIDRs {
		if cidr.Contains(parsed) {
			return false
		}
	}
	return true
}

//go:embed ui/index.html
var uiHTML []byte

var (
	dataDir         = envOrDefault("DATA_DIR", "/data/builds")
	alertmanagerURL = envOrDefault("ALERTMANAGER_URL", "")
	listenAddr      = envOrDefault("LISTEN_ADDR", ":8080")
	ingestSecret    = os.Getenv("INGEST_SECRET")
)

type whitelist struct {
	Global  []string            `json:"global"`
	PerStep map[string][]string `json:"per_step"`
}

var globalWhitelist *whitelist

func loadWhitelist() {
	path := os.Getenv("WHITELIST_PATH")
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("INFO: no whitelist at %s — whitelist checking disabled", path)
		return
	}
	var wl whitelist
	if err := json.Unmarshal(data, &wl); err != nil {
		log.Printf("WARN: invalid whitelist JSON at %s: %v", path, err)
		return
	}
	globalWhitelist = &wl
	log.Printf("INFO: loaded whitelist: %d global entries, %d per-step sets", len(wl.Global), len(wl.PerStep))
}

func isWhitelisted(binary, stepName string) bool {
	for _, b := range globalWhitelist.Global {
		if b == binary {
			return true
		}
	}
	for _, b := range globalWhitelist.PerStep[stepName] {
		if b == binary {
			return true
		}
	}
	return false
}

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
	loadWhitelist()
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
		go correlate(auditId, true)
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

// handleBuilds routes GET /builds/ (list), GET /builds/{id}/summary (detail),
// and POST /builds/{id}/recorrelate (re-run correlation).
func handleBuilds(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/builds/")
	if path == "" {
		handleBuildList(w, r)
		return
	}
	if strings.HasSuffix(path, "/recorrelate") {
		handleRecorrelate(w, r)
		return
	}
	if strings.HasSuffix(path, "/groovy") {
		handleBuildGroovy(w, r)
		return
	}
	handleBuildSummary(w, r)
}

func handleRecorrelate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkIngestAuth(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/builds/")
	auditId := strings.TrimSuffix(path, "/recorrelate")
	if auditId == "" || auditId == path {
		http.Error(w, "invalid path — expected /builds/{auditId}/recorrelate", http.StatusBadRequest)
		return
	}
	buildDir := filepath.Join(dataDir, auditId)
	if _, err := os.Stat(buildDir); os.IsNotExist(err) {
		http.Error(w, "build not found", http.StatusNotFound)
		return
	}
	correlate(auditId, false)
	data, err := os.ReadFile(filepath.Join(buildDir, "correlated.json"))
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
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

// handleBuildGroovy serves GET /builds/{auditId}/groovy — every GROOVY_CALLSITE class
// (pipeline + library) with its full call list, read from the raw event stream so the
// build summary stays lean. Powers the per-call-site drill-down in the UI.
func handleBuildGroovy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/builds/")
	auditId := strings.TrimSuffix(path, "/groovy")
	if auditId == "" || auditId == path {
		http.Error(w, "invalid path — expected /builds/{auditId}/groovy", http.StatusBadRequest)
		return
	}
	steps, err := readStepEvents(filepath.Join(dataDir, auditId, "events.ndjson"))
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	type csClass struct {
		Origin          string     `json:"origin"`
		Source          string     `json:"source"`
		Clazz           string     `json:"clazz"`
		CallCount       int        `json:"callCount"`
		SyscallGateways int        `json:"syscallGateways"`
		Calls           []callSite `json:"calls"`
	}
	out := []csClass{}
	for _, s := range steps {
		if s.Event == "GROOVY_CALLSITE" {
			out = append(out, csClass{s.Origin, s.Source, s.Clazz, s.CallCount, s.SyscallGateways, s.Calls})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(out)
}

// --- Correlation ----------------------------------------------------------------

type libraryRef struct {
	Source   string `json:"source,omitempty"`
	Library  string `json:"library,omitempty"`
	Version  string `json:"version,omitempty"`
	StepName string `json:"stepName,omitempty"`
}

type stepEvent struct {
	Event         string          `json:"event"`
	NodeId        string          `json:"nodeId"`
	StartNodeId   string          `json:"startNodeId"`
	StepName      string          `json:"stepName"`
	FunctionName  string          `json:"functionName"`
	TS            int64           `json:"ts"`
	Result        string          `json:"result"`
	DurationMs    *int64          `json:"durationMs,omitempty"`
	EnclosingIds  []string        `json:"enclosingIds,omitempty"`
	LibrarySource *libraryRef     `json:"librarySource,omitempty"`
	CalledFrom    *libraryRef     `json:"calledFrom,omitempty"`
	Arguments     json.RawMessage `json:"arguments,omitempty"`
	Origin              string     `json:"origin,omitempty"`
	Source              string     `json:"source,omitempty"`
	Clazz               string     `json:"clazz,omitempty"`
	Signature           string     `json:"signature,omitempty"`
	Provenance          string     `json:"provenance,omitempty"`
	SyscallGateways     int        `json:"syscallGateways,omitempty"`
	CallCount           int        `json:"callCount,omitempty"`
	JenkinsfileApproved *bool      `json:"jenkinsfileApproved,omitempty"`
	Findings            []string   `json:"findings,omitempty"`
	Calls               []callSite `json:"calls,omitempty"`
}

type stepNode struct {
	NodeId       string          `json:"nodeId"`
	StepName     string          `json:"stepName"`
	FunctionName string          `json:"functionName,omitempty"`
	StartTS      int64           `json:"startTs"`
	EndTS        int64           `json:"endTs,omitempty"`
	DurationMs   *int64          `json:"durationMs,omitempty"`
	Result       string          `json:"result,omitempty"`
	Library      *libraryRef     `json:"library,omitempty"`
	CalledFrom   *libraryRef     `json:"calledFrom,omitempty"`
	Arguments    json.RawMessage `json:"arguments,omitempty"`
	Children     []*stepNode     `json:"children,omitempty"`
}

type tetragonEvent struct {
	TS        int64  `json:"ts"`
	AuditId   string `json:"auditId"`
	EventType string `json:"event_type"`
	Binary    string `json:"binary"`
	Args      string `json:"args"`
	Pid       int    `json:"pid"`
	ParentPid int    `json:"parent_pid,omitempty"`
	DestIP    string `json:"dest_ip,omitempty"`
	DestPort  int    `json:"dest_port,omitempty"`
	Path      string `json:"path,omitempty"`
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

type correlatedNetwork struct {
	TetragonEvent tetragonEvent `json:"tetragon_event"`
	MatchedStep   *stepEvent    `json:"matched_step,omitempty"`
	Anomaly       bool          `json:"anomaly"`
	AnomalyReason string        `json:"anomaly_reason,omitempty"`
}

type correlatedFile struct {
	TetragonEvent tetragonEvent `json:"tetragon_event"`
	MatchedStep   *stepEvent    `json:"matched_step,omitempty"`
}

type correlatedHttp struct {
	HttpEvent   httpEvent  `json:"http_event"`
	MatchedStep *stepEvent `json:"matched_step,omitempty"`
}

type callSite struct {
	Line    int    `json:"line"`
	Kind    string `json:"kind"`
	Target  string   `json:"target"`
	Method  string   `json:"method"`
	Syscall string   `json:"syscall,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type groovyDeny struct {
	Signature  string `json:"signature"`
	Provenance string `json:"provenance,omitempty"`
}

type syscallSite struct {
	Origin  string   `json:"origin"`
	Source  string   `json:"source"`
	Line    int      `json:"line"`
	Target  string   `json:"target"`
	Method  string   `json:"method"`
	Syscall string   `json:"syscall"`
	Args    []string `json:"args,omitempty"`
}

type correlationReport struct {
	AuditId                string              `json:"audit_id"`
	GeneratedAt            string              `json:"generated_at"`
	TotalSteps             int                 `json:"total_steps"`
	TotalExecs             int                 `json:"total_execs"`
	AnomalyCount           int                 `json:"anomaly_count"`
	TotalGroovyCalls       int                 `json:"total_groovy_calls"`
	SandboxViolationCount  int                 `json:"sandbox_violation_count"`
	TotalGroovyCallSites   int                 `json:"total_groovy_call_sites"`
	SyscallGatewayCount    int                 `json:"syscall_gateway_count"`
	JenkinsfileApproved    *bool               `json:"jenkinsfile_approved,omitempty"`
	JenkinsfileFindings    []string            `json:"jenkinsfile_findings,omitempty"`
	GroovyDenies           []groovyDeny        `json:"groovy_denies,omitempty"`
	SyscallCallSites       []syscallSite       `json:"syscall_call_sites,omitempty"`
	TotalHttpRequests      int                 `json:"total_http_requests"`
	BlockedHttpRequests    int                 `json:"blocked_http_requests"`
	TotalNetworkEvents     int                 `json:"total_network_events"`
	UnexpectedNetworkCount int                 `json:"unexpected_network_count"`
	TotalFileOpens         int                 `json:"total_file_opens"`
	TotalPtrace            int                 `json:"total_ptrace"`
	StepTree               []*stepNode         `json:"step_tree"`
	CorrelatedExecs        []correlatedExec    `json:"correlated_execs"`
	CorrelatedHttp         []correlatedHttp    `json:"correlated_http,omitempty"`
	CorrelatedNetwork      []correlatedNetwork `json:"correlated_network,omitempty"`
	CorrelatedFiles        []correlatedFile    `json:"correlated_files,omitempty"`
	CorrelatedPtrace       []correlatedFile    `json:"correlated_ptrace,omitempty"`
}

// buildMeta is a stripped-down correlationReport used for the build list endpoint.
type buildMeta struct {
	AuditId                string `json:"audit_id"`
	GeneratedAt            string `json:"generated_at,omitempty"`
	TotalSteps             int    `json:"total_steps"`
	TotalExecs             int    `json:"total_execs"`
	AnomalyCount           int    `json:"anomaly_count"`
	TotalGroovyCalls       int    `json:"total_groovy_calls"`
	SandboxViolationCount  int    `json:"sandbox_violation_count"`
	TotalGroovyCallSites   int    `json:"total_groovy_call_sites"`
	SyscallGatewayCount    int    `json:"syscall_gateway_count"`
	TotalHttpRequests      int    `json:"total_http_requests"`
	BlockedHttpRequests    int    `json:"blocked_http_requests"`
	TotalNetworkEvents     int    `json:"total_network_events"`
	UnexpectedNetworkCount int    `json:"unexpected_network_count"`
	TotalFileOpens         int    `json:"total_file_opens"`
	TotalPtrace            int    `json:"total_ptrace"`
	InProgress             bool   `json:"in_progress,omitempty"`
}

func correlate(auditId string, wait bool) {
	if wait {
		// Brief pause so any in-flight POSTs from the build complete
		time.Sleep(2 * time.Second)
	}

	buildDir := filepath.Join(dataDir, auditId)

	steps, err := readStepEvents(filepath.Join(buildDir, "events.ndjson"))
	if err != nil {
		log.Printf("WARN correlate %s: reading steps: %v", auditId, err)
	}

	// Partition out PlatformGroovyInterceptor events (GROOVY_CALL/GROOVY_DENY).
	// They share events.ndjson with step events but are not pipeline steps, so they
	// must not enter the step-window/tree logic. A GROOVY_DENY is a blocked escape
	// primitive (ProcessBuilder/exec/reflection/...) and also counts as a call attempt.
	groovyCalls, sandboxViolations := 0, 0
	groovyCallSites, syscallGateways := 0, 0
	var jenkinsfileApproved *bool
	var jenkinsfileFindings []string
	groovyDenies := []groovyDeny{}
	syscallSites := []syscallSite{}
	filtered := steps[:0]
	for _, s := range steps {
		switch s.Event {
		case "GROOVY_CALL":
			groovyCalls++
		case "GROOVY_DENY":
			groovyCalls++
			sandboxViolations++
			if len(groovyDenies) < 200 {
				groovyDenies = append(groovyDenies, groovyDeny{Signature: s.Signature, Provenance: s.Provenance})
			}
		case "GROOVY_CALLSITE":
			groovyCallSites += s.CallCount
			syscallGateways += s.SyscallGateways
			for _, c := range s.Calls {
				if c.Syscall != "" && len(syscallSites) < 300 {
					syscallSites = append(syscallSites, syscallSite{
						Origin: s.Origin, Source: s.Source, Line: c.Line,
						Target: c.Target, Method: c.Method, Syscall: c.Syscall, Args: c.Args})
				}
			}
		case "JENKINSFILE_ANALYSIS":
			jenkinsfileApproved = s.JenkinsfileApproved
			jenkinsfileFindings = s.Findings
		default:
			filtered = append(filtered, s)
		}
	}
	steps = filtered

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

	// Pick the innermost (latest-starting) window that contains ts — avoids attributing
	// execs to the outermost enclosing block (e.g. podTemplate) when a more specific
	// step (e.g. a stage or sh) is also active at the same timestamp.
	matchStep := func(ts int64) *stepEvent {
		var best *stepEvent
		var bestStart int64
		for i := range windows {
			if ts >= windows[i].startTS && ts <= windows[i].endTS {
				if best == nil || windows[i].startTS > bestStart {
					s := windows[i].step
					best = &s
					bestStart = windows[i].startTS
				}
			}
		}
		return best
	}

	var correlated []correlatedExec
	var correlatedNet []correlatedNetwork
	var correlatedFiles []correlatedFile
	var correlatedPtrace []correlatedFile
	var anomalies []map[string]any

	for _, te := range tetEvents {
		if te.EventType == "network" {
			cn := correlatedNetwork{TetragonEvent: te}
			cn.MatchedStep = matchStep(te.TS)
			if isExternalIP(te.DestIP) {
				cn.Anomaly = true
				cn.AnomalyReason = fmt.Sprintf("direct TCP connection to external IP %s:%d (expected to route through proxy)", te.DestIP, te.DestPort)
				anomalies = append(anomalies, map[string]any{
					"audit_id":  auditId,
					"type":      "unexpected_network",
					"dest_ip":   te.DestIP,
					"dest_port": te.DestPort,
					"ts":        te.TS,
					"reason":    cn.AnomalyReason,
				})
				fireAlert("unexpected_network", map[string]any{
					"alertname":   "UnexpectedNetworkConnection",
					"severity":    "warning",
					"audit_id":    auditId,
					"dest_ip":     te.DestIP,
					"dest_port":   te.DestPort,
					"summary":     fmt.Sprintf("Direct external TCP connection during build %s: %s:%d", auditId, te.DestIP, te.DestPort),
					"description": "Build pod made a direct TCP connection to an external IP, bypassing the MITM proxy.",
				})
			}
			correlatedNet = append(correlatedNet, cn)
			continue
		}
		if te.EventType == "ptrace" {
			reason := "ptrace() during build — possible process/credential injection"
			anomalies = append(anomalies, map[string]any{
				"audit_id": auditId, "type": "ptrace", "binary": te.Binary,
				"ts": te.TS, "reason": reason,
			})
			fireAlert("ptrace", map[string]any{
				"alertname": "PtraceDuringBuild", "severity": "critical", "audit_id": auditId,
				"binary": te.Binary,
				"summary": fmt.Sprintf("ptrace during build %s by %s", auditId, te.Binary),
				"description": "A process attached to another via ptrace during the build — possible memory/credential scraping.",
			})
			correlatedPtrace = append(correlatedPtrace, correlatedFile{TetragonEvent: te, MatchedStep: matchStep(te.TS)})
			continue
		}
		if te.EventType == "file_open" {
			// Observability only: sensitive-file access needs path-allowlist calibration
			// before it feeds AnomalyCount (which is a HARD attest-gate forbid). Alert now,
			// gate later once false positives per podTemplate are tuned out.
			fireAlert("sensitive_file", map[string]any{
				"alertname": "SensitiveFileAccess", "severity": "warning", "audit_id": auditId,
				"path": te.Path, "binary": te.Binary,
				"summary": fmt.Sprintf("Sensitive file access during build %s: %s", auditId, te.Path),
				"description": "Build pod opened a credential-bearing path. Review before enabling as a hard gate.",
			})
			correlatedFiles = append(correlatedFiles, correlatedFile{TetragonEvent: te, MatchedStep: matchStep(te.TS)})
			continue
		}
		ce := correlatedExec{TetragonEvent: te}
		ce.MatchedStep = matchStep(te.TS)
		correlated = append(correlated, ce)
	}

	// PID lineage: build pid→parentPid and pid→matchedStep maps, then walk the
	// parent chain for execs that didn't match any step window by timestamp.
	// Handles long-running child processes that outlive their parent step window.
	pidParent := make(map[int]int)
	pidStep := make(map[int]*stepEvent)
	for i := range correlated {
		ce := &correlated[i]
		if ce.TetragonEvent.ParentPid != 0 {
			pidParent[ce.TetragonEvent.Pid] = ce.TetragonEvent.ParentPid
		}
		if ce.MatchedStep != nil {
			pidStep[ce.TetragonEvent.Pid] = ce.MatchedStep
		}
	}
	for i := range correlated {
		ce := &correlated[i]
		if ce.MatchedStep != nil {
			continue
		}
		pid := ce.TetragonEvent.ParentPid
		for depth := 0; depth < 5 && pid != 0; depth++ {
			if s, ok := pidStep[pid]; ok {
				ce.MatchedStep = s
				break
			}
			pid = pidParent[pid]
		}
	}

	// Flag execs still unmatched after lineage walk as undeclared.
	for i := range correlated {
		ce := &correlated[i]
		if ce.MatchedStep == nil {
			ce.Anomaly = true
			ce.AnomalyReason = "exec() occurred outside any declared pipeline step"
			anomalies = append(anomalies, map[string]any{
				"audit_id": auditId,
				"type":     "undeclared_exec",
				"binary":   ce.TetragonEvent.Binary,
				"args":     ce.TetragonEvent.Args,
				"ts":       ce.TetragonEvent.TS,
				"reason":   ce.AnomalyReason,
			})
			fireAlert("undeclared_exec", map[string]any{
				"alertname":   "UndeclaredExec",
				"severity":    "critical",
				"audit_id":    auditId,
				"binary":      ce.TetragonEvent.Binary,
				"summary":     fmt.Sprintf("Undeclared exec() during build %s: %s", auditId, ce.TetragonEvent.Binary),
				"description": "A process executed outside any declared pipeline step. Possible supply chain injection.",
			})
		}
	}

	// Whitelist check: flag binaries within step windows that aren't on the allowlist.
	if globalWhitelist != nil {
		for i := range correlated {
			ce := &correlated[i]
			if ce.MatchedStep == nil || ce.Anomaly {
				continue
			}
			if !isWhitelisted(ce.TetragonEvent.Binary, ce.MatchedStep.StepName) {
				ce.Anomaly = true
				ce.AnomalyReason = fmt.Sprintf("binary %s not in whitelist for step %s", ce.TetragonEvent.Binary, ce.MatchedStep.StepName)
				anomalies = append(anomalies, map[string]any{
					"audit_id": auditId,
					"type":     "unexpected_binary",
					"binary":   ce.TetragonEvent.Binary,
					"step":     ce.MatchedStep.StepName,
					"ts":       ce.TetragonEvent.TS,
					"reason":   ce.AnomalyReason,
				})
				fireAlert("unexpected_binary", map[string]any{
					"alertname": "UnexpectedBinary",
					"severity":  "warning",
					"audit_id":  auditId,
					"binary":    ce.TetragonEvent.Binary,
					"step":      ce.MatchedStep.StepName,
					"summary":   fmt.Sprintf("Unlisted binary during build %s: %s in step %s", auditId, ce.TetragonEvent.Binary, ce.MatchedStep.StepName),
				})
			}
		}
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

	unexpectedNetCount := 0
	for _, cn := range correlatedNet {
		if cn.Anomaly {
			unexpectedNetCount++
		}
	}

	report := correlationReport{
		AuditId:                auditId,
		GeneratedAt:            time.Now().UTC().Format(time.RFC3339Nano),
		TotalSteps:             len(windows),
		TotalExecs:             len(correlated),
		AnomalyCount:           len(anomalies),
		TotalGroovyCalls:       groovyCalls,
		SandboxViolationCount:  sandboxViolations,
		TotalGroovyCallSites:   groovyCallSites,
		SyscallGatewayCount:    syscallGateways,
		JenkinsfileApproved:    jenkinsfileApproved,
		JenkinsfileFindings:    jenkinsfileFindings,
		GroovyDenies:           groovyDenies,
		SyscallCallSites:       syscallSites,
		TotalHttpRequests:      len(httpEvents),
		BlockedHttpRequests:    blockedCount,
		TotalNetworkEvents:     len(correlatedNet),
		UnexpectedNetworkCount: unexpectedNetCount,
		TotalFileOpens:         len(correlatedFiles),
		TotalPtrace:            len(correlatedPtrace),
		StepTree:               buildStepTree(steps),
		CorrelatedExecs:        correlated,
		CorrelatedHttp:         correlHttp,
		CorrelatedNetwork:      correlatedNet,
		CorrelatedFiles:        correlatedFiles,
		CorrelatedPtrace:       correlatedPtrace,
	}

	writeJSON(filepath.Join(buildDir, "correlated.json"), report)
	if len(anomalies) > 0 {
		writeJSON(filepath.Join(buildDir, "anomalies.json"), anomalies)
	}

	log.Printf("correlation complete %s: steps=%d execs=%d http=%d blocked=%d anomalies=%d groovy=%d denied=%d callsites=%d syscall_gw=%d",
		auditId, report.TotalSteps, report.TotalExecs, report.TotalHttpRequests, blockedCount, report.AnomalyCount, report.TotalGroovyCalls, report.SandboxViolationCount, report.TotalGroovyCallSites, report.SyscallGatewayCount)
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
			Arguments:    s.Arguments,
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

	// Phase 3.5: insert STEP_ATOM events as leaf nodes under their nearest enclosing
	// STEP_START parent. Atoms with no enclosing block are dropped (not shown at root).
	for _, s := range steps {
		if s.Event != "STEP_ATOM" {
			continue
		}
		n := &stepNode{
			NodeId:       s.NodeId,
			StepName:     s.StepName,
			FunctionName: s.FunctionName,
			StartTS:      s.TS,
			Library:      s.LibrarySource,
			CalledFrom:   s.CalledFrom,
			Arguments:    s.Arguments,
		}
		for _, encId := range s.EnclosingIds {
			if parent, ok := nodesByStart[encId]; ok {
				parent.Children = append(parent.Children, n)
				break
			}
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
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(alertmanagerURL+"/api/v2/alerts", "application/json",
			strings.NewReader(string(body)))
		if err != nil {
			log.Printf("ALERT fire failed (%s): %v — alert: %v", alertName, err, fields)
			return
		}
		resp.Body.Close()
	}()
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
