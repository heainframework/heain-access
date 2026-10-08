package keycard

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

func open(t *testing.T) *Store {
	s, _ := heain.NewSealer(bytes.Repeat([]byte{7}, 32))
	st, err := Open(filepath.Join(t.TempDir(), "k.db"), s, bytes.Repeat([]byte{3}, 32), Params{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestKeycardAnomaly(t *testing.T) {
	st := open(t)
	// three weeks of office hours: 12 cards, in at about 08:30-09:20 through the lobby, out about 17:30 by the garage
	mon := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	st.Now = func() time.Time { return mon.AddDate(0, 0, 22) }
	for d := 0; d < 21; d++ {
		day := mon.AddDate(0, 0, d)
		if wd := day.Weekday(); wd == time.Saturday || wd == time.Sunday {
			continue
		}
		for c := 0; c < 12; c++ {
			in := day.Add(8*time.Hour + time.Duration(30+(c*7+d*3)%50)*time.Minute)
			out := day.Add(17*time.Hour + time.Duration(20+(c*5+d)%30)*time.Minute)
			for _, sw := range []Swipe{{At: in, Reader: "lobby", Allowed: true}, {At: out, Reader: "garage", Allowed: true}} {
				if err := st.Record(fmt.Sprintf("card-%02d", c), sw); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	h, _ := st.History("card-03")
	if len(h) != 30 || h[0].F == nil {
		t.Fatalf("history %d", len(h))
	}
	// a usual Monday morning, and a Sunday 03:10 at the server room
	usual, err := st.Score("card-03", "lobby", mon.AddDate(0, 0, 21).Add(8*time.Hour+50*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	odd, _ := st.Score("card-03", "server-room", mon.AddDate(0, 0, 20).Add(3*time.Hour+10*time.Minute))
	if usual.Status != "scored" || usual.Flagged || odd.Status != "scored" || !odd.Flagged || odd.Score <= usual.Score+0.1 {
		t.Fatalf("usual %+v\nodd %+v", usual, odd)
	}
	if odd.Features["reader_novelty"] != 1 || odd.Features["hour_distance_h"] < 5 {
		t.Fatalf("features %+v", odd.Features)
	}
	// a new card has no history: not scored, not flagged
	nw, _ := st.Score("card-new", "server-room", mon.AddDate(0, 0, 20).Add(3*time.Hour))
	if nw.Status != "insufficient_history" || nw.Flagged {
		t.Fatalf("new card %+v", nw)
	}
	// retention: swipes older than it are dropped
	st.P.Retention = 7 * 24 * time.Hour
	if h, _ := st.History("card-03"); len(h) != 8 { // Tue 29 Sep to Fri 2 Oct
		t.Fatalf("after a 7-day retention: %d swipes", len(h))
	}
	if st.Card("card-03") == st.Card("card-04") || len(st.Card("x")) != 64 || st.ModelSHA256() == "" {
		t.Fatal("card hmac / model hash")
	}
}
