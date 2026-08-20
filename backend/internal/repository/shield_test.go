package repository

import (
	"encoding/json"
	"strings"
	"testing"
)

func shieldBodyForTest() []byte {
	return []byte(`{"model":"gpt-5.4","instructions":"You are Codex.","prompt_cache_key":"old-session-123","previous_response_id":"resp_prev_456","input":[{"role":"user","content":"继续任务"}]}`)
}

func TestShieldTransformStripsSessionIDs(t *testing.T) {
	out, changed := shieldTransformBody(shieldBodyForTest())
	if !changed {
		t.Fatal("expected change")
	}
	var req map[string]interface{}
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatal(err)
	}
	if _, exists := req["prompt_cache_key"]; exists {
		t.Fatal("prompt_cache_key should be stripped")
	}
	if _, exists := req["previous_response_id"]; exists {
		t.Fatal("previous_response_id should be stripped")
	}
}

func TestShieldTransformBoostsInstructions(t *testing.T) {
	out, _ := shieldTransformBody(shieldBodyForTest())
	var req map[string]interface{}
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatal(err)
	}
	instr, _ := req["instructions"].(string)
	if !strings.Contains(instr, "OUTPUT DISCIPLINE") {
		t.Fatal("instructions boost missing")
	}
}

func TestShieldTransformNoTrim(t *testing.T) {
	// 确认不再做历史裁剪：大 input 原样保留
	big := `{"model":"gpt-5.4","instructions":"x","input":[{"role":"user","content":"` +
		strings.Repeat("很长的历史内容。", 50000) + `"}]}`
	out, _ := shieldTransformBody([]byte(big))
	if len(out) < 100000 {
		t.Fatal("history should NOT be trimmed")
	}
}

func TestShieldDisabledByDefault(t *testing.T) {
	if shieldEnabled() {
		t.Fatal("shield must be off by default (opt-in via S2A_SHIELD=1)")
	}
}
