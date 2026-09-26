package webpanel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

type fingerprintFamilyVariant struct {
	JA3              string   `json:"ja3"`
	JA3Hash          string   `json:"ja3_hash"`
	JA4              string   `json:"ja4"`
	TLSState         string   `json:"tls_state,omitempty"`
	ProfileID        string   `json:"profile_id,omitempty"`
	ProfileVersion   uint64   `json:"profile_version,omitempty"`
	ProfileFamilyID  string   `json:"profile_family_id,omitempty"`
	HTTPFingerprints []string `json:"http_fingerprints,omitempty"`
	ObservationIDs   []string `json:"observation_ids"`
}

type fingerprintFamily struct {
	ID               string                     `json:"id"`
	DeviceID         string                     `json:"device_id"`
	ApplicationID    string                     `json:"application_id,omitempty"`
	Application      string                     `json:"application,omitempty"`
	Evidence         string                     `json:"evidence"`
	ObservationCount int                        `json:"observation_count"`
	Variants         []fingerprintFamilyVariant `json:"variants"`
}

type managedProfileVariant struct {
	ProfileID   string `json:"profile_id"`
	Name        string `json:"name"`
	Version     uint64 `json:"version"`
	ProfileType string `json:"profile_type,omitempty"`
	JA3         string `json:"ja3,omitempty"`
	JA4         string `json:"ja4,omitempty"`
}

type managedProfileFamily struct {
	FamilyID string                  `json:"family_id"`
	Evidence string                  `json:"evidence"`
	Profiles []managedProfileVariant `json:"profiles"`
}

func (panel Server) fingerprintFamilies(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	observations, scope, err := loadFamilyObservations(panel.Recorder, filter)
	if err != nil {
		writeStoredQueryError(w, err)
		return
	}
	profiles := []managedProfileFamily{}
	if panel.Profiles != nil {
		profiles = buildManagedProfileFamilies(panel.Profiles.Snapshot().Templates)
	}
	profileFamilyIDs := make(map[string]string)
	for _, family := range profiles {
		for _, profile := range family.Profiles {
			profileFamilyIDs[profile.ProfileID] = family.FamilyID
		}
	}
	families := buildFingerprintFamilies(observations)
	for i := range families {
		for j := range families[i].Variants {
			families[i].Variants[j].ProfileFamilyID = profileFamilyIDs[families[i].Variants[j].ProfileID]
		}
	}
	_ = json.NewEncoder(w).Encode(struct {
		Items           []fingerprintFamily    `json:"items"`
		ProfileFamilies []managedProfileFamily `json:"profile_families"`
		Scope           string                 `json:"scope"`
	}{Items: families, ProfileFamilies: profiles, Scope: scope})
}

func loadFamilyObservations(source *recorder.Recorder, filter observationFilter) ([]recorder.Observation, string, error) {
	query := recorder.StoredQuery{
		Limit: 100, DeviceID: filter.DeviceID, Application: filter.Application,
		ApplicationID: filter.ApplicationID, ApplicationVersion: filter.ApplicationVersion,
		AnalysisRevision: filter.AnalysisRevision, From: filter.From, To: filter.To,
	}
	observations := make([]recorder.Observation, 0)
	scope := "sqlite_history_plus_recent"
	for {
		page, err := source.QueryStored(query)
		if errors.Is(err, recorder.ErrHistoricalUnavailable) {
			return filteredObservations(source.Snapshot(), filter), "recent_in_memory_observations", nil
		}
		if err != nil {
			return nil, "", err
		}
		for _, observation := range page.Items {
			observations = append(observations, compactFamilyObservation(observation))
		}
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}

	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		seen[observation.ID] = struct{}{}
	}
	for _, observation := range filteredObservations(source.Snapshot(), filter) {
		if _, exists := seen[observation.ID]; exists {
			continue
		}
		observations = append(observations, compactFamilyObservation(observation))
	}
	return observations, scope, nil
}

func compactFamilyObservation(observation recorder.Observation) recorder.Observation {
	observation.Raw = nil
	observation.Records = nil
	observation.RawServerHello = nil
	observation.ServerRecords = nil
	observation.ServerHello = nil
	if observation.Hello != nil {
		observation.Hello = &tlshello.Hello{HandshakeType: observation.Hello.HandshakeType}
	}
	observation.RuntimeMutations = nil
	observation.Routing = nil
	observation.Expected = nil
	observation.Forwarded = nil
	return observation
}

func buildManagedProfileFamilies(templates []tlsprofile.Template) []managedProfileFamily {
	grouped := make(map[string][]managedProfileVariant)
	for _, template := range templates {
		familyID := strings.TrimSpace(template.FamilyID)
		if familyID == "" {
			continue
		}
		variant := managedProfileVariant{
			ProfileID: template.ID, Name: template.Name, Version: template.Version,
			ProfileType: template.ProfileType,
		}
		if template.Expected != nil {
			variant.JA3, variant.JA4 = template.Expected.JA3, template.Expected.JA4
		}
		grouped[familyID] = append(grouped[familyID], variant)
	}
	families := make([]managedProfileFamily, 0, len(grouped))
	for familyID, variants := range grouped {
		if len(variants) < 2 {
			continue
		}
		sort.Slice(variants, func(i, j int) bool {
			if variants[i].ProfileID != variants[j].ProfileID {
				return variants[i].ProfileID < variants[j].ProfileID
			}
			return variants[i].Version < variants[j].Version
		})
		families = append(families, managedProfileFamily{
			FamilyID: familyID,
			Evidence: "явная связь: одинаковый family_id задан в сохранённых TLS-профилях",
			Profiles: variants,
		})
	}
	sort.Slice(families, func(i, j int) bool { return families[i].FamilyID < families[j].FamilyID })
	return families
}

// Automatic families intentionally require a resolved device and an inbound
// client observation. This prevents unrelated clients and the proxy's own
// outbound ClientHello from being grouped by a weak application-name match.
func buildFingerprintFamilies(observations []recorder.Observation) []fingerprintFamily {
	type group struct {
		family   fingerprintFamily
		variants map[string]*fingerprintFamilyVariant
	}
	groups := make(map[string]*group)
	connectionVariants := make(map[string]*fingerprintFamilyVariant)
	for _, observation := range observations {
		if observation.Fingerprints == nil || observation.ResolvedDeviceID == "" || observation.CapturePoint != "CLIENT_IN" || observation.Direction != "inbound" {
			continue
		}
		appKey := observation.ApplicationID
		if appKey == "" {
			appKey = strings.ToLower(strings.TrimSpace(observation.Application))
		}
		if appKey == "" {
			continue
		}
		key := observation.ResolvedDeviceID + "\x00" + appKey
		hash := sha256.Sum256([]byte(key))
		id := "ff-" + hex.EncodeToString(hash[:8])
		g := groups[key]
		if g == nil {
			g = &group{
				family: fingerprintFamily{
					ID: id, DeviceID: observation.ResolvedDeviceID,
					ApplicationID: observation.ApplicationID, Application: observation.Application,
					Evidence: "совпадают разрешённый device_id и стабильный application_id/name; учитываются только CLIENT_IN/inbound",
				},
				variants: make(map[string]*fingerprintFamilyVariant),
			}
			groups[key] = g
		}
		tlsState := ""
		if observation.Hello != nil {
			switch observation.Hello.HandshakeType {
			case "FULL":
				tlsState = "FULL"
			case "RESUMED":
				tlsState = "RESUMED"
			case "PSK":
				tlsState = "PSK"
			}
		}
		if observation.NegotiatedState != nil {
			switch {
			case observation.NegotiatedState.SessionResumption:
				tlsState = "RESUMED"
			case strings.EqualFold(observation.NegotiatedState.HandshakeType, "PSK"):
				tlsState = "PSK"
			case observation.NegotiatedState.HandshakeComplete:
				tlsState = "FULL"
			}
		}
		variantKey := observation.Fingerprints.JA3 + "\x00" + observation.Fingerprints.JA3Hash + "\x00" + observation.Fingerprints.JA4 + "\x00" + tlsState + "\x00" + observation.ProfileID + "\x00" + strconv.FormatUint(observation.ProfileVersion, 10)
		variant := g.variants[variantKey]
		if variant == nil {
			variant = &fingerprintFamilyVariant{
				JA3: observation.Fingerprints.JA3, JA3Hash: observation.Fingerprints.JA3Hash,
				JA4: observation.Fingerprints.JA4, TLSState: tlsState,
				ProfileID: observation.ProfileID, ProfileVersion: observation.ProfileVersion,
				ObservationIDs: []string{},
			}
			g.variants[variantKey] = variant
		}
		variant.ObservationIDs = append(variant.ObservationIDs, observation.ID)
		if observation.ConnectionID != "" {
			connectionVariants[observation.ConnectionID] = variant
		}
		if observation.HTTP1 != nil {
			value := "HTTP/1"
			if observation.HTTP1.Method != "" {
				value += " " + observation.HTTP1.Method
			}
			variant.HTTPFingerprints = appendUnique(variant.HTTPFingerprints, value)
		}
		if observation.HTTP2 != nil && observation.HTTP2.Hash != "" {
			variant.HTTPFingerprints = appendUnique(variant.HTTPFingerprints, "HTTP/2 "+observation.HTTP2.Hash)
		}
	}
	// HTTP captures are separate observations. Associate them only by the
	// recorder-generated connection ID, never by time proximity or destination.
	for _, observation := range observations {
		if observation.ConnectionID == "" || observation.CapturePoint != "CLIENT_IN" || observation.Direction != "inbound" {
			continue
		}
		variant := connectionVariants[observation.ConnectionID]
		if variant == nil {
			continue
		}
		if observation.HTTP1 != nil {
			label := observation.HTTP1.HTTPVersion
			if label == "" {
				label = "HTTP/1"
			}
			if observation.HTTP1.Method != "" {
				label += " " + observation.HTTP1.Method
			}
			variant.HTTPFingerprints = appendUnique(variant.HTTPFingerprints, label)
			variant.ObservationIDs = appendUnique(variant.ObservationIDs, observation.ID)
		}
		if observation.HTTP2 != nil && observation.HTTP2.Hash != "" {
			variant.HTTPFingerprints = appendUnique(variant.HTTPFingerprints, "HTTP/2 "+observation.HTTP2.Hash)
			variant.ObservationIDs = appendUnique(variant.ObservationIDs, observation.ID)
		}
	}

	families := make([]fingerprintFamily, 0, len(groups))
	for _, g := range groups {
		for _, variant := range g.variants {
			sort.Strings(variant.HTTPFingerprints)
			sort.Strings(variant.ObservationIDs)
			g.family.ObservationCount += len(variant.ObservationIDs)
			g.family.Variants = append(g.family.Variants, *variant)
		}
		sort.Slice(g.family.Variants, func(i, j int) bool {
			if g.family.Variants[i].JA4 != g.family.Variants[j].JA4 {
				return g.family.Variants[i].JA4 < g.family.Variants[j].JA4
			}
			return g.family.Variants[i].TLSState < g.family.Variants[j].TLSState
		})
		families = append(families, g.family)
	}
	sort.Slice(families, func(i, j int) bool { return families[i].ID < families[j].ID })
	return families
}

func appendUnique(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}
