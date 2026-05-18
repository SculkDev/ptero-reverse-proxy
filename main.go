package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	BaseDomain      string
	LabelDelimiter  string
	PanelURL        string
	PanelAPIKey     string
	ListenAddr      string
	UpstreamScheme  string
	RefreshInterval time.Duration
	TrustForwarded  bool
	PerPage         int
}

func loadConfig() (*Config, error) {
	c := &Config{
		BaseDomain:      strings.ToLower(strings.Trim(os.Getenv("BASE_DOMAIN"), ".")),
		LabelDelimiter:  getEnv("LABEL_DELIMITER", "--"),
		PanelURL:        strings.TrimRight(os.Getenv("PANEL_URL"), "/"),
		PanelAPIKey:     os.Getenv("PANEL_API_KEY"),
		ListenAddr:      getEnv("LISTEN_ADDR", ":8080"),
		UpstreamScheme:  getEnv("UPSTREAM_SCHEME", "https"),
		RefreshInterval: 30 * time.Minute,
		TrustForwarded:  os.Getenv("TRUST_FORWARDED") == "1",
		PerPage:         25,
	}
	if v := os.Getenv("REFRESH_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid REFRESH_INTERVAL %q: %w", v, err)
		}
		c.RefreshInterval = d
	}
	if v := os.Getenv("PER_PAGE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid PER_PAGE %q", v)
		}
		c.PerPage = n
	}
	if c.BaseDomain == "" {
		return nil, errors.New("BASE_DOMAIN required (e.g. example.com)")
	}
	if c.LabelDelimiter == "" {
		return nil, errors.New("LABEL_DELIMITER must not be empty")
	}
	if strings.Contains(c.LabelDelimiter, ".") {
		return nil, errors.New("LABEL_DELIMITER must not contain '.'")
	}
	if c.PanelURL == "" {
		return nil, errors.New("PANEL_URL required (e.g. https://your-panel.com)")
	}
	if c.PanelAPIKey == "" {
		return nil, errors.New("PANEL_API_KEY required")
	}
	return c, nil
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type Whitelist struct {
	v atomic.Value
}

func (w *Whitelist) Set(ips map[string]struct{}) { w.v.Store(ips) }

func (w *Whitelist) Has(ip string) bool {
	m, _ := w.v.Load().(map[string]struct{})
	if m == nil {
		return false
	}
	_, ok := m[ip]
	return ok
}

func (w *Whitelist) Size() int {
	m, _ := w.v.Load().(map[string]struct{})
	return len(m)
}

type nodesResponse struct {
	Data []struct {
		Attributes struct {
			FQDN string `json:"fqdn"`
		} `json:"attributes"`
	} `json:"data"`
	Meta struct {
		Pagination struct {
			TotalPages  int `json:"total_pages"`
			CurrentPage int `json:"current_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

func fetchFQDNs(ctx context.Context, cfg *Config) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var fqdns []string
	for page := 1; ; page++ {
		endpoint := fmt.Sprintf(
			"%s/api/application/nodes?include=location,allocations&per_page=%d&page=%d",
			cfg.PanelURL, cfg.PerPage, page,
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.PanelAPIKey)
		req.Header.Set("Accept", "Application/vnd.pterodactyl.v1+json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page, err)
		}
		if resp.StatusCode/100 != 2 {
			resp.Body.Close()
			return nil, fmt.Errorf("page %d: panel returned %s", page, resp.Status)
		}
		var nr nodesResponse
		err = json.NewDecoder(resp.Body).Decode(&nr)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("page %d decode: %w", page, err)
		}
		for _, n := range nr.Data {
			if f := strings.TrimSpace(n.Attributes.FQDN); f != "" {
				fqdns = append(fqdns, f)
			}
		}
		if nr.Meta.Pagination.TotalPages == 0 ||
			nr.Meta.Pagination.CurrentPage >= nr.Meta.Pagination.TotalPages {
			break
		}
	}
	return fqdns, nil
}

func resolveIPs(ctx context.Context, fqdns []string) map[string]struct{} {
	out := make(map[string]struct{})
	resolver := net.DefaultResolver
	for _, f := range fqdns {
		if ip := net.ParseIP(f); ip != nil {
			out[ip.String()] = struct{}{}
			continue
		}
		addrs, err := resolver.LookupIPAddr(ctx, f)
		if err != nil {
			log.Printf("lookup %s: %v", f, err)
			continue
		}
		for _, a := range addrs {
			out[a.IP.String()] = struct{}{}
		}
	}
	return out
}

func refreshLoop(ctx context.Context, cfg *Config, wl *Whitelist) {
	run := func() {
		c, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		fqdns, err := fetchFQDNs(c, cfg)
		if err != nil {
			log.Printf("whitelist refresh: fetch nodes: %v", err)
			return
		}
		ips := resolveIPs(c, fqdns)
		wl.Set(ips)
		log.Printf("whitelist refreshed: %d fqdns -> %d ips", len(fqdns), len(ips))
	}
	run()
	t := time.NewTicker(cfg.RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func clientIP(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			return strings.TrimSpace(xrip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type proxyServer struct {
	cfg    *Config
	wl     *Whitelist
	suffix string

	mu    sync.RWMutex
	cache map[string]*httputil.ReverseProxy
}

func newProxyServer(cfg *Config, wl *Whitelist) *proxyServer {
	return &proxyServer{
		cfg:    cfg,
		wl:     wl,
		suffix: "." + cfg.BaseDomain,
		cache:  make(map[string]*httputil.ReverseProxy),
	}
}

func (s *proxyServer) proxyFor(target string) *httputil.ReverseProxy {
	s.mu.RLock()
	if p, ok := s.cache[target]; ok {
		s.mu.RUnlock()
		return p
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.cache[target]; ok {
		return p
	}
	u := &url.URL{Scheme: s.cfg.UpstreamScheme, Host: target}
	p := httputil.NewSingleHostReverseProxy(u)
	origDirector := p.Director
	p.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target
	}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("upstream %s: %v", target, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	s.cache[target] = p
	return p
}

func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, s.cfg.TrustForwarded)
	if !s.wl.Has(ip) {
		log.Printf("403 %s %s%s", ip, r.Host, r.URL.RequestURI())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.HasSuffix(host, s.suffix) {
		http.Error(w, "unknown host", http.StatusBadRequest)
		return
	}
	encoded := strings.TrimSuffix(host, s.suffix)
	if encoded == "" || strings.Contains(encoded, ".") {
		// Reject extra subdomain levels — encoded host must be a single label.
		http.Error(w, "unknown host", http.StatusBadRequest)
		return
	}
	target := strings.ReplaceAll(encoded, s.cfg.LabelDelimiter, ".")
	if target == "" ||
		strings.HasPrefix(target, ".") ||
		strings.HasSuffix(target, ".") ||
		strings.Contains(target, "..") {
		http.Error(w, "unknown host", http.StatusBadRequest)
		return
	}
	s.proxyFor(target).ServeHTTP(w, r)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	wl := &Whitelist{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go refreshLoop(ctx, cfg, wl)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newProxyServer(cfg, wl),
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("kgamesproxy listening on %s (base=%s, delim=%q, upstream=%s, refresh=%s, trust_xff=%v)",
		cfg.ListenAddr, cfg.BaseDomain, cfg.LabelDelimiter, cfg.UpstreamScheme, cfg.RefreshInterval, cfg.TrustForwarded)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
