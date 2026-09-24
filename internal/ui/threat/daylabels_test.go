// Copyright (C) 2026 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later

package threat

import (
	"strings"
	"testing"

	threatstore "github.com/nethesis/nethesis-insights/internal/store/threat"
	"github.com/nethesis/nethesis-insights/internal/ui/chrome"
)

// The oldest retained day is exactly the one the rolling prune cuts mid-day
// (THREAT_EVENT_RETENTION does not align with a day boundary), so its total
// is missing however much of the day was already pruned. The page must say
// so rather than presenting it as a complete day's total.
func TestStatsPageLabelsTheOldestDayAsPartial(t *testing.T) {
	r := threatReader()
	// testRetention (168h) back from testNow (2026-08-28T10:00:00Z) lands the
	// cutoff at 2026-08-21T10:00:00Z, ten hours into 2026-08-21 -- so that
	// day's row describes only its second half.
	r.threatDaily = []threatstore.ThreatDailyRow{
		{Day: "2026-08-21", Scenario: "crowdsecurity/ssh-bf", DistinctIPs: 1, TotalHits: 1},
	}
	h, err := NewServer(r, nil, nil, nil, chrome.Config{Info: testInfo()}, testRetention, testClock)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body := get(t, h, "/stats").Body.String()
	if !strings.Contains(body, "partial") {
		t.Fatalf("/stats did not label the oldest retained day as partial:\n%s", body)
	}
}

// Today, UTC, has not finished yet, so its total necessarily undercounts
// whatever happens for the rest of the day.
func TestStatsPageLabelsTodayAsInProgress(t *testing.T) {
	r := threatReader()
	r.threatDaily = []threatstore.ThreatDailyRow{
		// 2026-08-28 is "today" under testClock.
		{Day: "2026-08-28", Scenario: "crowdsecurity/ssh-bf", DistinctIPs: 1, TotalHits: 1},
	}
	h, err := NewServer(r, nil, nil, nil, chrome.Config{Info: testInfo()}, testRetention, testClock)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body := get(t, h, "/stats").Body.String()
	if !strings.Contains(body, "in progress") {
		t.Fatalf("/stats did not label today as in progress:\n%s", body)
	}
}

// An ordinary retained day -- neither the oldest nor today -- carries
// neither label. threatReader's own fixture ("2026-08-27") is exactly this
// case under testNow/testRetention.
func TestStatsPageHasNoPartialOrInProgressLabelForAnOrdinaryDay(t *testing.T) {
	h := newTestServerWithFeed(t, threatReader(), nil)
	body := get(t, h, "/stats").Body.String()
	if strings.Contains(body, "partial") || strings.Contains(body, "in progress") {
		t.Fatalf("/stats labeled an ordinary retained day:\n%s", body)
	}
}
