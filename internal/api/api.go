// Package api serves heain-access's capabilities over the heain-sdk
// direct-endpoint server (mTLS, app certificates, formal audit in core).
//
// Identity verification (lane "identity"): enrolment and matching of face
// and fingerprint templates, ID-card OCR with an optional check against a
// reference registry held by heain-database, and keycards against an ACL
// dataset held by heain-database. A successful verification yields a
// one-time verification id; an AccessGrant is issued against it. Every AI
// decision (face, fingerprint, OCR) sends a signed reasoning record.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-access/internal/biometric"
	"github.com/heainframework/heain-access/internal/grants"
	"github.com/heainframework/heain-access/internal/keycard"
	"github.com/heainframework/heain-access/internal/plugins/dcpkey"
	"github.com/heainframework/heain-access/internal/sidecar"
)

// API ties the stores, sidecars and plugin to the endpoints.
type API struct {
	App    *heain.App
	Side   *sidecar.Client
	Bio    *biometric.Store
	Grants *grants.Store
	KDM    *dcpkey.Issuer // nil: the dcp-key plugin is not enabled
	// KDMCallers are the apps allowed to ask for a KDM (the plugin signs
	// whatever content keys it is given).
	KDMCallers map[string]bool
	Runtime    string // sidecar description for reasoning records

	FaceThreshold   float64       // cosine similarity
	FingerThreshold float64       // sidecar score
	Retention       time.Duration // template retention (<= 30 days)
	ACLDataset      string        // default keycard ACL dataset in heain-database
	ACLScope        string
	Keycards        *keycard.Store // the keycard anomaly signal (Stage B-3a)

	mu    sync.Mutex
	verif map[string]verification
}

type verification struct {
	Subject, Method string
	At              time.Time
}

// VerificationTTL is how long a verification id can be used for a grant.
var VerificationTTL = 10 * time.Minute

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "retryable": status >= 500}})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

// Register adds every endpoint of the manifest to s.
func (a *API) Register(s *heain.Server) error {
	a.verif = map[string]verification{}
	for p, f := range map[string]http.HandlerFunc{
		"POST /v1/enroll/face":          a.enrollFace,
		"POST /v1/enroll/fingerprint":   a.enrollFinger,
		"DELETE /v1/subjects/{subject}": a.removeSubject,
		"POST /v1/verify/face":          a.verifyFace,
		"POST /v1/verify/fingerprint":   a.verifyFinger,
		"POST /v1/verify/id-card":       a.verifyIDCard,
		"POST /v1/verify/keycard":       a.verifyKeycard,
		"POST /v1/grants":               a.issueGrant,
		"GET /v1/grants/{id}":           a.getGrant,
		"POST /v1/grants/{id}/check":    a.checkGrant,
		"DELETE /v1/grants/{id}":        a.revokeGrant,
		"POST /v1/plugins/dcp-key/kdm":  a.issueKDM,
	} {
		if err := s.HandleFunc(p, f); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) newVerification(subject, method string) string {
	id := heain.NewID()
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.verif {
		if now.Sub(v.At) > VerificationTTL {
			delete(a.verif, k)
		}
	}
	a.verif[id] = verification{Subject: subject, Method: method, At: now}
	return id
}

func (a *API) takeVerification(id string) (verification, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.verif[id]
	delete(a.verif, id)
	return v, ok && time.Since(v.At) <= VerificationTTL
}

func (a *API) reason(ctx context.Context, capability string, input []byte, decision string, conf float64, thr *heain.Threshold, summary string, factors []heain.Factor, value map[string]any) error {
	base := a.Side.Face
	switch {
	case strings.Contains(capability, "fingerprint"):
		base = a.Side.Finger
	case strings.HasSuffix(capability, "idcard"):
		base = a.Side.OCR
	}
	model, err := a.Side.ModelSHA256(ctx, base)
	if err != nil {
		return err
	}
	c := math.Max(0, math.Min(1, conf))
	_, err = a.App.Reason(ctx, heain.Decision{Capability: capability, Input: input, InputDataClass: "biometric_template",
		Decision: decision, Value: value, Threshold: thr, Confidence: &c, Summary: summary, Factors: factors, Role: "decision",
		ModelSHA256: model, Runtime: a.Runtime})
	return err
}

// ---- enrolment

type enrollReq struct {
	Subject string `json:"subject"`
	Image   []byte `json:"image_b64"`
}

func (a *API) enrolled(w http.ResponseWriter, t biometric.Template) {
	reply(w, http.StatusCreated, map[string]any{"enrolled": true, "method": t.Method, "expires_at": t.ExpiresAt})
}

func (a *API) enrollFace(w http.ResponseWriter, r *http.Request) {
	var b enrollReq
	if !decode(w, r, &b) {
		return
	}
	if b.Subject == "" || len(b.Image) == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "subject and image_b64 are required")
		return
	}
	emb, found, det, err := a.Side.EmbedFace(r.Context(), b.Image)
	if err != nil {
		fail(w, http.StatusBadGateway, "sidecar_unavailable", err.Error())
		return
	}
	if !found {
		fail(w, http.StatusUnprocessableEntity, "no_face", "no face found in the image")
		return
	}
	data, _ := json.Marshal(emb)
	t, err := a.Bio.Enroll(r.Context(), b.Subject, "face", data, a.Retention)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := a.reason(r.Context(), "identity.enroll.face", b.Image, "face template enrolled", det, nil,
		"The image was reduced to an embedding by the face model; only the embedding is kept, sealed, until its retention ends.",
		[]heain.Factor{{Name: "detection_score", Value: det}, {Name: "embedding_dims", Value: len(emb)}, {Name: "retention_h", Value: a.Retention.Hours()}}, nil); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	a.enrolled(w, t)
}

func (a *API) enrollFinger(w http.ResponseWriter, r *http.Request) {
	var b enrollReq
	if !decode(w, r, &b) {
		return
	}
	if b.Subject == "" || len(b.Image) == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "subject and image_b64 are required")
		return
	}
	tm, err := a.Side.FingerTemplate(r.Context(), b.Image)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "no_template", err.Error())
		return
	}
	t, err := a.Bio.Enroll(r.Context(), b.Subject, "fingerprint", tm, a.Retention)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := a.reason(r.Context(), "identity.enroll.fingerprint", b.Image, "fingerprint template enrolled", 1, nil,
		"The image was reduced to a minutiae template; only the template is kept, sealed, until its retention ends.",
		[]heain.Factor{{Name: "template_bytes", Value: len(tm)}, {Name: "retention_h", Value: a.Retention.Hours()}}, nil); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	a.enrolled(w, t)
}

func (a *API) removeSubject(w http.ResponseWriter, r *http.Request) {
	gone, err := a.Bio.Remove(r.Context(), r.PathValue("subject"))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"removed": gone})
}

// ---- verification

type verifyOut struct {
	Allow          bool    `json:"allow"`
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason,omitempty"`
	VerificationID string  `json:"verification_id,omitempty"`
	// keycards (Stage B-3a): the advisory anomaly signal, and the P5
	// review raised when it flags the swipe
	Anomaly        *keycard.Result `json:"anomaly,omitempty"`
	ReviewActionID string          `json:"review_action_id,omitempty"`
}

func cosine(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var d, x, y float64
	for i := range a {
		d, x, y = d+a[i]*b[i], x+a[i]*a[i], y+b[i]*b[i]
	}
	if x == 0 || y == 0 {
		return 0
	}
	return d / math.Sqrt(x*y)
}

func (a *API) verifyFace(w http.ResponseWriter, r *http.Request) {
	var b enrollReq
	if !decode(w, r, &b) {
		return
	}
	t, err := a.Bio.Get(r.Context(), b.Subject, "face")
	if errors.Is(err, biometric.ErrNotEnrolled) {
		fail(w, http.StatusNotFound, "not_enrolled", "no live face template for this subject")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var enrolled []float64
	_ = json.Unmarshal(t.Data, &enrolled)
	emb, found, det, err := a.Side.EmbedFace(r.Context(), b.Image)
	if err != nil {
		fail(w, http.StatusBadGateway, "sidecar_unavailable", err.Error())
		return
	}
	sim := 0.0
	if found {
		sim = cosine(emb, enrolled)
	}
	out := verifyOut{Allow: found && sim >= a.FaceThreshold, Confidence: math.Round(math.Max(0, sim)*1000) / 1000}
	switch {
	case !found:
		out.Reason = "no face found in the image"
	case !out.Allow:
		out.Reason = fmt.Sprintf("similarity %.3f is below the threshold %.3f", sim, a.FaceThreshold)
	}
	decision := map[bool]string{true: "match", false: "no match"}[out.Allow]
	if err := a.reason(r.Context(), "identity.verify.face", b.Image, decision, math.Max(0, sim),
		&heain.Threshold{Name: "cosine_similarity", Value: a.FaceThreshold, Source: "app"},
		"Cosine similarity between the presented face embedding and the enrolled one, against the threshold.",
		[]heain.Factor{{Name: "similarity", Value: math.Round(sim*10000) / 10000}, {Name: "face_detected", Value: found}, {Name: "detection_score", Value: det}},
		map[string]any{"allow": out.Allow}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if out.Allow {
		out.VerificationID = a.newVerification(b.Subject, "face")
	}
	reply(w, http.StatusOK, out)
}

func (a *API) verifyFinger(w http.ResponseWriter, r *http.Request) {
	var b enrollReq
	if !decode(w, r, &b) {
		return
	}
	t, err := a.Bio.Get(r.Context(), b.Subject, "fingerprint")
	if errors.Is(err, biometric.ErrNotEnrolled) {
		fail(w, http.StatusNotFound, "not_enrolled", "no live fingerprint template for this subject")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	score, err := a.Side.FingerMatch(r.Context(), b.Image, t.Data)
	if err != nil {
		fail(w, http.StatusBadGateway, "sidecar_unavailable", err.Error())
		return
	}
	out := verifyOut{Allow: score >= a.FingerThreshold, Confidence: math.Round(score*1000) / 1000}
	if !out.Allow {
		out.Reason = fmt.Sprintf("match score %.3f is below the threshold %.3f", score, a.FingerThreshold)
	}
	if err := a.reason(r.Context(), "identity.verify.fingerprint", b.Image, map[bool]string{true: "match", false: "no match"}[out.Allow], score,
		&heain.Threshold{Name: "match_score", Value: a.FingerThreshold, Source: "app"},
		"Minutiae match score of the presented fingerprint against the enrolled template, against the threshold.",
		[]heain.Factor{{Name: "score", Value: math.Round(score*10000) / 10000}}, map[string]any{"allow": out.Allow}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if out.Allow {
		out.VerificationID = a.newVerification(b.Subject, "fingerprint")
	}
	reply(w, http.StatusOK, out)
}

var nonDigits = regexp.MustCompile(`[^0-9A-Za-z]`)

func normID(s string) string { return strings.ToUpper(nonDigits.ReplaceAllString(s, "")) }

type registryRef struct {
	Dataset  string `json:"dataset"`
	ScopeKey string `json:"scope_key"`
}

// lookup asks heain-database for record key in a dataset scope; found
// false on 404.
func (a *API) lookup(ctx context.Context, ref registryRef, key string) (map[string]any, bool, error) {
	var rec struct {
		Value map[string]any `json:"value"`
	}
	_, err := a.App.Call(ctx, heain.CallSpec{App: "heain-database", Capability: "db.dataset.lookup", Method: "GET",
		Path: "/v1/datasets/" + url.PathEscape(ref.Dataset) + "/records/" + url.PathEscape(key) + "?scope_key=" + url.QueryEscape(ref.ScopeKey), Out: &rec})
	var ce *heain.CallError
	if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return rec.Value, true, nil
}

func (a *API) verifyIDCard(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Image    []byte       `json:"image_b64"`
		Expected string       `json:"expected_id_number"`
		Registry *registryRef `json:"registry,omitempty"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Image) == 0 || b.Expected == "" {
		fail(w, http.StatusBadRequest, "bad_request", "image_b64 and expected_id_number are required")
		return
	}
	text, conf, err := a.Side.ExtractText(r.Context(), b.Image)
	if err != nil {
		fail(w, http.StatusBadGateway, "sidecar_unavailable", err.Error())
		return
	}
	read := strings.Contains(normID(text), normID(b.Expected))
	out := verifyOut{Allow: read, Confidence: math.Round(conf*1000) / 1000}
	factors := []heain.Factor{{Name: "number_found_on_card", Value: read}, {Name: "ocr_confidence", Value: math.Round(conf*1000) / 1000}}
	if !read {
		out.Reason = "the expected id number was not read on the card"
	}
	if read && b.Registry != nil {
		val, found, err := a.lookup(r.Context(), *b.Registry, normID(b.Expected))
		if err != nil {
			fail(w, http.StatusBadGateway, "registry_unavailable", err.Error())
			return
		}
		eligible := found && val["eligible"] != false
		factors = append(factors, heain.Factor{Name: "in_registry", Value: found}, heain.Factor{Name: "registry", Value: b.Registry.Dataset + "/" + b.Registry.ScopeKey})
		if !eligible {
			out.Allow = false
			out.Reason = map[bool]string{true: "listed in the registry as not eligible", false: "not in the registry"}[found]
		}
	}
	if err := a.reason(r.Context(), "identity.verify.idcard", b.Image, map[bool]string{true: "verified", false: "not verified"}[out.Allow], conf, nil,
		"OCR of the card must contain the expected id number; when a registry is named, heain-database must list it (and not as ineligible).",
		factors, map[string]any{"allow": out.Allow}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if out.Allow {
		out.VerificationID = a.newVerification(normID(b.Expected), "id_card")
	}
	reply(w, http.StatusOK, out)
}

func (a *API) verifyKeycard(w http.ResponseWriter, r *http.Request) {
	var b struct {
		UID    string       `json:"uid"`
		ACL    *registryRef `json:"acl,omitempty"`
		Reader string       `json:"reader,omitempty"` // the door or reader (default "default")
		At     *time.Time   `json:"at,omitempty"`     // when the card was read (a reader may upload its log late); default now
	}
	if !decode(w, r, &b) {
		return
	}
	if b.UID == "" {
		fail(w, http.StatusBadRequest, "bad_request", "uid is required")
		return
	}
	now := time.Now().UTC()
	at := now
	if b.At != nil {
		if b.At.After(now.Add(5 * time.Minute)) {
			fail(w, http.StatusBadRequest, "bad_request", "at is in the future")
			return
		}
		at = b.At.UTC()
	}
	if b.Reader == "" {
		b.Reader = "default"
	}
	ref := registryRef{Dataset: a.ACLDataset, ScopeKey: a.ACLScope}
	if b.ACL != nil {
		ref = *b.ACL
	}
	val, found, err := a.lookup(r.Context(), ref, b.UID)
	if err != nil {
		var ce *heain.CallError
		if !errors.As(err, &ce) {
			fail(w, http.StatusBadGateway, "acl_unavailable", err.Error())
			return
		}
	}
	// the ACL is the gate: the model below never changes this decision
	out := verifyOut{Allow: found && val["allowed"] != false, Confidence: 1}
	if !out.Allow {
		out.Confidence, out.Reason = 0, "keycard not on the ACL"
	}
	if a.Keycards != nil {
		res, err := a.Keycards.Score(b.UID, b.Reader, at)
		if err == nil {
			err = a.Keycards.Record(b.UID, keycard.Swipe{At: at, Reader: b.Reader, Allowed: out.Allow})
		}
		if err == nil {
			out.Anomaly = &res
			err = a.keycardRecord(r.Context(), b.UID, b.Reader, at, out.Allow, res, &out)
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if out.Allow {
		out.VerificationID = a.newVerification(b.UID, "keycard")
	}
	reply(w, http.StatusOK, out)
}

// keycardRecord files the swipe's signed reasoning record and, when the
// model flags it, asks an Approver to review it (P5, advisory).
func (a *API) keycardRecord(ctx context.Context, uid, reader string, at time.Time, allow bool, res keycard.Result, out *verifyOut) error {
	card := a.Keycards.Card(uid)
	gate := "deny (not on the ACL)"
	if allow {
		gate = "allow (on the ACL)"
	}
	decision := gate + "; anomaly not scored: too little history"
	if res.Status == "scored" {
		decision = fmt.Sprintf("%s; anomaly score %.3f (%s)", gate, res.Score, map[bool]string{true: "flagged for review", false: "usual"}[res.Flagged])
	}
	var factors []heain.Factor
	for _, n := range keycard.FeatureNames {
		factors = append(factors, heain.Factor{Name: n, Value: res.Features[n]})
	}
	factors = append(factors, heain.Factor{Name: "card_history", Value: res.History}, heain.Factor{Name: "fitted_swipes", Value: res.Fitted})
	conf := 1.0
	if res.Status == "scored" {
		conf = 1 - res.Score
	}
	if _, err := a.App.Reason(ctx, heain.Decision{Capability: "identity.verify.keycard", Input: []byte(card + "|" + reader + "|" + at.Format(time.RFC3339Nano)),
		InputDataClass: "keycard_history", InputRef: "keycard:" + card[:16], Decision: decision,
		Value:     map[string]any{"allow": allow, "anomaly": res.Status, "score": res.Score, "flagged": res.Flagged},
		Threshold: &heain.Threshold{Name: "anomaly_score", Value: res.Threshold, Source: "app"}, Confidence: &conf,
		Summary: "The ACL decides; an Isolation Forest over the card's own history (time of day, weekday, reader, gap, burst, recent denials) scores how unusual the swipe is, advisory only.",
		Factors: factors, Role: "advisory", ModelSHA256: a.Keycards.ModelSHA256(), Runtime: "heain-access keycard iforest (go)"}); err != nil {
		return err
	}
	if !res.Flagged {
		return nil
	}
	pr, err := a.App.Propose(ctx, heain.Proposal{Type: "access.keycard_review", Category: heain.CategoryThreshold, Value: res.Score,
		Data: map[string]any{"card": card[:16], "reader": reader, "at": at, "allowed": allow, "score": res.Score, "features": res.Features}})
	if err != nil {
		return err
	}
	out.ReviewActionID = pr.ActionID
	return nil
}

// ---- grants

func (a *API) issueGrant(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Recipient      string    `json:"recipient"`
		AssetRef       string    `json:"asset_ref"`
		ValidFrom      time.Time `json:"valid_from"`
		ValidUntil     time.Time `json:"valid_until"`
		VerificationID string    `json:"verification_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	v, ok := a.takeVerification(b.VerificationID)
	if !ok {
		fail(w, http.StatusForbidden, "verification_required", "a successful verification from the last 10 minutes is required, once")
		return
	}
	g, err := a.Grants.Issue(grants.Grant{Recipient: b.Recipient, AssetRef: b.AssetRef, ValidFrom: b.ValidFrom, ValidUntil: b.ValidUntil,
		Method: v.Method, VerificationID: b.VerificationID})
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	reply(w, http.StatusCreated, g)
}

func (a *API) getGrant(w http.ResponseWriter, r *http.Request) {
	g, err := a.Grants.Get(r.PathValue("id"))
	if errors.Is(err, grants.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such grant")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, g)
}

func (a *API) checkGrant(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AssetRef string `json:"asset_ref"`
	}
	if !decode(w, r, &b) {
		return
	}
	ok, why, err := a.Grants.Check(r.PathValue("id"), b.AssetRef)
	if errors.Is(err, grants.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such grant")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := map[string]any{"valid": ok}
	if !ok {
		out["reason"] = why
	}
	reply(w, http.StatusOK, out)
}

func (a *API) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := a.Grants.Revoke(r.PathValue("id")); errors.Is(err, grants.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such grant")
		return
	} else if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"revoked": true})
}

// ---- dcp-key plugin

func (a *API) issueKDM(w http.ResponseWriter, r *http.Request) {
	if a.KDM == nil {
		fail(w, http.StatusNotImplemented, "plugin_not_enabled", "the dcp-key plugin is not enabled on this instance")
		return
	}
	c := heain.Caller(r.Context())
	if i := strings.IndexByte(c, '.'); i > 0 {
		c = c[:i]
	}
	if !a.KDMCallers[c] {
		fail(w, http.StatusForbidden, "forbidden", "app "+c+" may not ask for KDMs (-dcp-key-callers)")
		return
	}
	var b dcpkey.Request
	if !decode(w, r, &b) {
		return
	}
	res, err := a.KDM.Issue(r.Context(), b)
	if err != nil {
		var br *dcpkey.BadRequest
		if errors.As(err, &br) {
			fail(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !res.Allow {
		reply(w, http.StatusOK, map[string]any{"issued": false, "reason": res.Reason})
		return
	}
	reply(w, http.StatusOK, map[string]any{"issued": true, "kdm_xml": string(res.KDM), "message_id": res.MessageID, "recipient": res.Recipient})
}
