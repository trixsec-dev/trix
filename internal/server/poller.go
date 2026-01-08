package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/davealtena/trix/internal/tools/kubectl"
	"github.com/davealtena/trix/internal/tools/trivy"
)

// VulnerabilityEvent represents a change in vulnerability state.
type VulnerabilityEvent struct {
	ID              string     `json:"ID"`
	Type            string     `json:"Type"` // NEW, FIXED
	CVE             string     `json:"CVE"`
	Workload        string     `json:"Workload"`
	Severity        string     `json:"Severity"`
	Image           string     `json:"Image"` // package:version (legacy)
	ContainerName   string     `json:"ContainerName,omitempty"`
	ImageRepository string     `json:"ImageRepository,omitempty"`
	ImageTag        string     `json:"ImageTag,omitempty"`
	ImageDigest     string     `json:"ImageDigest,omitempty"`
	FirstSeen       time.Time  `json:"FirstSeen"`
	FixedAt         *time.Time `json:"FixedAt,omitempty"`
}

// Poller periodically scans Trivy CRDs and detects changes.
type Poller struct {
	trivyClient *trivy.Client
	db          *DB
	config      *Config
	logger      *slog.Logger
}

// NewPoller creates a new Trivy CRD poller.
func NewPoller(db *DB, config *Config, logger *slog.Logger) (*Poller, error) {
	k8sClient, err := kubectl.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	trivyClient := trivy.NewClient(k8sClient)

	return &Poller{
		trivyClient: trivyClient,
		db:          db,
		config:      config,
		logger:      logger,
	}, nil
}

// Poll performs a single poll of Trivy CRDs and returns events.
func (p *Poller) Poll(ctx context.Context) ([]VulnerabilityEvent, error) {
	p.logger.Info("starting poll")

	// Get all findings from Trivy
	findings, err := p.getFindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	p.logger.Info("found vulnerabilities", "count", len(findings))

	var events []VulnerabilityEvent
	var currentIDs []string

	// Process each finding
	for _, f := range findings {
		record := p.findingToRecord(f)
		currentIDs = append(currentIDs, record.ID)

		isNew, err := p.db.UpsertVulnerability(ctx, record)
		if err != nil {
			p.logger.Error("failed to upsert vulnerability", "id", record.ID, "error", err)
			continue
		}

		if isNew {
			events = append(events, VulnerabilityEvent{
				ID:              record.ID,
				Type:            "NEW",
				CVE:             record.CVE,
				Workload:        record.Workload,
				Severity:        record.Severity,
				Image:           record.Image,
				ContainerName:   record.ContainerName,
				ImageRepository: record.ImageRepository,
				ImageTag:        record.ImageTag,
				ImageDigest:     record.ImageDigest,
				FirstSeen:       time.Now(),
			})
		}
	}

	// Mark vulnerabilities not in current scan as fixed
	fixed, err := p.db.MarkFixed(ctx, currentIDs)
	if err != nil {
		p.logger.Error("failed to mark fixed vulnerabilities", "error", err)
	} else {
		for _, v := range fixed {
			events = append(events, VulnerabilityEvent{
				ID:              v.ID,
				Type:            "FIXED",
				CVE:             v.CVE,
				Workload:        v.Workload,
				Severity:        v.Severity,
				Image:           v.Image,
				ContainerName:   v.ContainerName,
				ImageRepository: v.ImageRepository,
				ImageTag:        v.ImageTag,
				ImageDigest:     v.ImageDigest,
				FirstSeen:       v.FirstSeen,
				FixedAt:         v.FixedAt,
			})
		}
	}

	p.logger.Info("poll complete", "new", countByType(events, "NEW"), "fixed", countByType(events, "FIXED"))

	return events, nil
}

// getFindings retrieves all vulnerability findings from Trivy CRDs.
func (p *Poller) getFindings(ctx context.Context) ([]trivy.Finding, error) {
	// Use the existing scanner infrastructure
	scanners := []trivy.Scanner{
		trivy.NewTrivyVulnScanner(p.trivyClient),
		trivy.NewClusterVulnScanner(p.trivyClient),
	}

	var allFindings []trivy.Finding

	for _, scanner := range scanners {
		if len(p.config.Namespaces) > 0 {
			// Scan specific namespaces
			for _, ns := range p.config.Namespaces {
				findings, err := scanner.Scan(ctx, ns)
				if err != nil {
					p.logger.Warn("scanner failed", "scanner", scanner.Name(), "namespace", ns, "error", err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		} else {
			// Scan all namespaces
			findings, err := scanner.Scan(ctx, "")
			if err != nil {
				p.logger.Warn("scanner failed", "scanner", scanner.Name(), "error", err)
				continue
			}
			allFindings = append(allFindings, findings...)
		}
	}

	// Filter to only vulnerability type
	var vulnFindings []trivy.Finding
	for _, f := range allFindings {
		if f.Type == trivy.FindingTypeVulnerability {
			vulnFindings = append(vulnFindings, f)
		}
	}

	return vulnFindings, nil
}

// findingToRecord converts a Trivy finding to a database record.
func (p *Poller) findingToRecord(f trivy.Finding) *VulnerabilityRecord {
	workload := fmt.Sprintf("%s/%s/%s", f.Namespace, f.ResourceKind, f.ResourceName)

	// Extract package info from raw data
	pkgName := ""
	pkgVersion := ""
	if raw, ok := f.RawData.(trivy.Vulnerability); ok {
		pkgName = raw.PkgName
		pkgVersion = raw.InstalledVersion
	}

	// Create unique ID from CVE + workload + package + container
	// Including container ensures same CVE in different containers of same workload are tracked separately
	idHash := sha256.Sum256([]byte(f.ID + workload + pkgName + f.ContainerName))
	id := fmt.Sprintf("%x", idHash[:8])

	image := ""
	if pkgName != "" {
		image = fmt.Sprintf("%s:%s", pkgName, pkgVersion)
	}

	return &VulnerabilityRecord{
		ID:              id,
		CVE:             f.ID,
		Workload:        workload,
		Severity:        string(f.Severity),
		Image:           image,
		ContainerName:   f.ContainerName,
		ImageRepository: f.ImageRepository,
		ImageTag:        f.ImageTag,
		ImageDigest:     f.ImageDigest,
		State:           StateOpen,
	}
}

func countByType(events []VulnerabilityEvent, eventType string) int {
	count := 0
	for _, e := range events {
		if e.Type == eventType {
			count++
		}
	}
	return count
}
