// Package keycard is the keycard anomaly signal (Stage B-3a, author
// decisions 2026-10-08; design note 2026-10-02): the ACL stays the hard,
// deterministic gate -- a card not on it is never let in, and the model
// never overrides a deny -- and each swipe gets an advisory score of how
// unlike that card's own history it is.
//
// A swipe is described against the card's earlier swipes: how far its
// time of day is from any earlier one, how new its weekday and its reader
// are for the card, the gap since the card's last swipe, a burst (swipes
// in the last ten minutes) and the denials of the last day. An Isolation
// Forest fitted on recent swipes of every card (each described against its
// own card's history at the time) scores the new one: near 1 = easily
// isolated = unusual. Swipe history is kept sealed per card, under an HMAC
// of the card id, for at most the retention (default 90 days).
package keycard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-access/internal/iforest"
)

// FeatureNames name the features, in order.
var FeatureNames = []string{"hour_distance_h", "weekday_novelty", "reader_novelty", "gap_log_s", "burst_10min", "denied_24h"}

// Swipe is one keycard read.
type Swipe struct {
	At      time.Time `json:"at"`
	Reader  string    `json:"reader"`
	Allowed bool      `json:"allowed"`
	F       []float64 `json:"f"` // its features against the card's history at the time
}

// Features describe a swipe at reader, at time at, against earlier swipes.
func Features(past []Swipe, at time.Time, reader string) []float64 {
	tod := func(t time.Time) float64 { return float64(t.Hour()) + float64(t.Minute())/60 }
	hourDist, sameDay, sameReader := 12.0, 0, 0
	burst, denied := 0, 0
	gap := math.Log1p(30 * 24 * 3600)
	for _, p := range past {
		d := math.Abs(tod(p.At) - tod(at))
		hourDist = math.Min(hourDist, math.Min(d, 24-d))
		if p.At.Weekday() == at.Weekday() {
			sameDay++
		}
		if p.Reader == reader {
			sameReader++
		}
		if dt := at.Sub(p.At); dt >= 0 && dt <= 10*time.Minute {
			burst++
		}
		if dt := at.Sub(p.At); !p.Allowed && dt >= 0 && dt <= 24*time.Hour {
			denied++
		}
	}
	if n := len(past); n > 0 {
		gap = math.Log1p(math.Max(0, at.Sub(past[n-1].At).Seconds()))
	}
	share := func(k int) float64 {
		if len(past) == 0 {
			return 1
		}
		return 1 - float64(k)/float64(len(past))
	}
	return []float64{hourDist, share(sameDay), share(sameReader), gap, float64(burst), float64(denied)}
}

var bucket = []byte("keycards")

// Params of the model.
type Params struct {
	Threshold      float64       // advisory flag at or above (default 0.65)
	MinCardHistory int           // swipes a card needs before it is scored (default 10)
	MinRows        int           // swipes (all cards) the forest needs (default 50)
	Rows           int           // most recent swipes fitted (default 4096)
	Retention      time.Duration // history kept (default 90 days)
	MaxPerCard     int           // swipes kept per card (default 1000)
	RefitEvery     int           // refit after this many new swipes (default 50)
	Trees, Sample  int
}

func (p *Params) defaults() {
	if p.Threshold <= 0 {
		p.Threshold = 0.65
	}
	if p.MinCardHistory <= 0 {
		p.MinCardHistory = 10
	}
	if p.MinRows <= 0 {
		p.MinRows = 50
	}
	if p.Rows <= 0 {
		p.Rows = 4096
	}
	if p.Retention <= 0 {
		p.Retention = 90 * 24 * time.Hour
	}
	if p.MaxPerCard <= 0 {
		p.MaxPerCard = 1000
	}
	if p.RefitEvery <= 0 {
		p.RefitEvery = 50
	}
	if p.Trees <= 0 {
		p.Trees = 100
	}
	if p.Sample <= 0 {
		p.Sample = 256
	}
}

// Store keeps each card's swipes, sealed, and the fitted model.
type Store struct {
	db  *bolt.DB
	s   *heain.Sealer
	mac []byte
	P   Params
	Now func() time.Time

	mu      sync.Mutex
	forest  *iforest.Forest
	fitRows int
	added   int // swipes since the last fit
}

// Open opens the store; insideKey derives the HMAC for card ids.
func Open(path string, s *heain.Sealer, insideKey []byte, p Params) (*Store, error) {
	p.defaults()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("keycard: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(bucket); return err }); err != nil {
		_ = db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, insideKey)
	m.Write([]byte("heain-access/keycard/v1"))
	return &Store{db: db, s: s, mac: m.Sum(nil), P: p, Now: time.Now}, nil
}

// Close closes the file.
func (st *Store) Close() error { return st.db.Close() }

// Card is the HMAC a card id is filed under (and named by in records).
func (st *Store) Card(uid string) string {
	m := hmac.New(sha256.New, st.mac)
	m.Write([]byte(uid))
	return hex.EncodeToString(m.Sum(nil))
}

func (st *Store) read(tx *bolt.Tx, card string) []Swipe {
	v := tx.Bucket(bucket).Get([]byte(card))
	if v == nil {
		return nil
	}
	b, err := st.s.Open(v, []byte("keycard/"+card))
	if err != nil {
		return nil
	}
	var out []Swipe
	_ = json.Unmarshal(b, &out)
	return out
}

func (st *Store) prune(sw []Swipe) []Swipe {
	cut := st.Now().Add(-st.P.Retention)
	i := 0
	for i < len(sw) && sw[i].At.Before(cut) {
		i++
	}
	sw = sw[i:]
	if len(sw) > st.P.MaxPerCard {
		sw = sw[len(sw)-st.P.MaxPerCard:]
	}
	return sw
}

// History is a card's kept swipes, oldest first.
func (st *Store) History(uid string) ([]Swipe, error) {
	var out []Swipe
	err := st.db.View(func(tx *bolt.Tx) error { out = st.read(tx, st.Card(uid)); return nil })
	return st.prune(out), err
}

// Record adds a swipe (its features against the card's history before it).
func (st *Store) Record(uid string, sw Swipe) error {
	card := st.Card(uid)
	err := st.db.Update(func(tx *bolt.Tx) error {
		h := st.read(tx, card)
		// keep time order (a reader may upload its log late)
		i := sort.Search(len(h), func(i int) bool { return h[i].At.After(sw.At) })
		if sw.F == nil {
			sw.F = Features(h[:i], sw.At, sw.Reader)
		}
		h = append(h[:i], append([]Swipe{sw}, h[i:]...)...)
		h = st.prune(h)
		b, _ := json.Marshal(h)
		return tx.Bucket(bucket).Put([]byte(card), st.s.Seal(b, []byte("keycard/"+card)))
	})
	if err == nil {
		st.mu.Lock()
		st.added++
		st.mu.Unlock()
	}
	return err
}

// rows are the features of the most recent swipes of every card.
func (st *Store) rows() ([][]float64, string, error) {
	type r struct {
		at time.Time
		f  []float64
	}
	var all []r
	err := st.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, _ []byte) error {
			for _, sw := range st.prune(st.read(tx, string(k))) {
				if len(sw.F) == len(FeatureNames) {
					all = append(all, r{sw.At, sw.F})
				}
			}
			return nil
		})
	})
	sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	if len(all) > st.P.Rows {
		all = all[:st.P.Rows]
	}
	h := sha256.New()
	out := make([][]float64, len(all))
	for i, x := range all {
		out[i] = x.f
		_ = binary.Write(h, binary.BigEndian, x.at.UnixNano())
	}
	return out, hex.EncodeToString(h.Sum(nil)), err
}

// ModelSHA256 names the model in reasoning records: its kind, its
// parameters and its features.
func (st *Store) ModelSHA256() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("keycard-iforest/1 trees=%d sample=%d threshold=%g min_card=%d min_rows=%d rows=%d features=%v",
		st.P.Trees, st.P.Sample, st.P.Threshold, st.P.MinCardHistory, st.P.MinRows, st.P.Rows, FeatureNames)))
	return hex.EncodeToString(h[:])
}

// Result is a swipe's advisory anomaly signal.
type Result struct {
	Status    string             `json:"status"` // scored | insufficient_history
	Score     float64            `json:"score,omitempty"`
	Flagged   bool               `json:"flagged"`
	Threshold float64            `json:"threshold"`
	History   int                `json:"card_history"`
	Fitted    int                `json:"fitted_swipes"`
	Features  map[string]float64 `json:"features"`
}

// Score scores a swipe of uid at reader, time at, against that card's
// history (it does not record it).
func (st *Store) Score(uid, reader string, at time.Time) (Result, error) {
	h, err := st.History(uid)
	if err != nil {
		return Result{}, err
	}
	past := h[:sort.Search(len(h), func(i int) bool { return h[i].At.After(at) })]
	f := Features(past, at, reader)
	res := Result{Status: "insufficient_history", Threshold: st.P.Threshold, History: len(past), Features: map[string]float64{}}
	for i, n := range FeatureNames {
		res.Features[n] = math.Round(f[i]*1000) / 1000
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.forest == nil || st.added >= st.P.RefitEvery {
		rows, digest, err := st.rows()
		if err != nil {
			return res, err
		}
		st.forest, st.fitRows, st.added = nil, len(rows), 0
		if len(rows) >= st.P.MinRows {
			seed := int64(binary.BigEndian.Uint64([]byte(digest[:16])) >> 1)
			st.forest = iforest.Fit(rows, iforest.Params{Trees: st.P.Trees, Sample: st.P.Sample, Seed: seed})
		}
	}
	res.Fitted = st.fitRows
	if st.forest == nil || len(past) < st.P.MinCardHistory {
		return res, nil
	}
	res.Status = "scored"
	res.Score = math.Round(st.forest.Score(f)*1000) / 1000
	res.Flagged = res.Score >= st.P.Threshold
	return res, nil
}
