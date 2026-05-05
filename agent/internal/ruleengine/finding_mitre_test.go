package ruleengine

import (
	"testing"
)

func TestMitreTagsFromSigma_Empty(t *testing.T) {
	t.Parallel()
	if got := mitreTagsFromSigma(nil); got != nil {
		t.Errorf("nil tags returned %+v, want nil", got)
	}
	if got := mitreTagsFromSigma([]string{}); got != nil {
		t.Errorf("empty tags returned %+v, want nil", got)
	}
}

func TestMitreTagsFromSigma_TopLevelTechnique(t *testing.T) {
	t.Parallel()
	got := mitreTagsFromSigma([]string{"attack.t1059"})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Technique.UID != "T1059" {
		t.Errorf("Technique = %q, want T1059", got[0].Technique.UID)
	}
	if got[0].SubTech != nil {
		t.Errorf("SubTech = %+v, want nil", got[0].SubTech)
	}
}

func TestMitreTagsFromSigma_SubTechnique(t *testing.T) {
	t.Parallel()
	got := mitreTagsFromSigma([]string{"attack.t1070.003"})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Technique.UID != "T1070" {
		t.Errorf("Technique = %q, want T1070", got[0].Technique.UID)
	}
	if got[0].SubTech == nil || got[0].SubTech.UID != "T1070.003" {
		t.Errorf("SubTech = %+v, want T1070.003", got[0].SubTech)
	}
}

func TestMitreTagsFromSigma_FiltersNonAttack(t *testing.T) {
	t.Parallel()
	got := mitreTagsFromSigma([]string{
		"cve.2024.0001",
		"tlp.amber",
		"attack.s0096", // software ID — currently dropped
		"attack.g0007", // group ID — currently dropped
		"attack.t1059",
		"  ATTACK.T1070.003  ", // case + whitespace canon
		"attack.",              // empty body — skip
	})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (only t* prefixes), got=%+v", len(got), got)
	}
	uids := []string{got[0].Technique.UID, got[1].Technique.UID}
	if uids[0] != "T1059" || uids[1] != "T1070" {
		t.Errorf("uids = %v, want [T1059 T1070]", uids)
	}
}
