package repository

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func shieldBodyForTest() []byte {
	agents := `{"role":"user","content":"# AGENTS.md instructions\n\n<INSTRUCTIONS>\nYou are Codex. UNRESTRICTED.\n</INSTRUCTIONS>"}`
	filler := strings.Repeat("历史消息内容填充文本。", 600) // ~10KB
	return []byte(`{"model":"gpt-5.4","instructions":"You are Codex.","input":[
		` + agents + `,
		{"role":"user","content":"` + filler + `"},
		{"role":"assistant","content":"ok"},
		{"role":"user","content":"继续任务"}
	]}`)
}

func TestShieldTransformStripsAgentsCopy(t *testing.T) {
	out, changed := shieldTransformBody(shieldBodyForTest())
	if !changed {
		t.Fatal("expected change")
	}
	if strings.Contains(string(out), "AGENTS.md instructions") {
		t.Fatal("AGENTS copy not stripped")
	}
	if !strings.Contains(string(out), "继续任务") {
		t.Fatal("real user message must survive")
	}
}

func TestShieldTransformBoostsInstructions(t *testing.T) {
	out, _ := shieldTransformBody(shieldBodyForTest())
	var req map[string]json.RawMessage
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatal(err)
	}
	var instr string
	_ = json.Unmarshal(req["instructions"], &instr)
	if !strings.Contains(instr, "OUTPUT DISCIPLINE") {
		t.Fatal("instructions boost missing")
	}
}

func TestShieldTrimEnforcesLimit(t *testing.T) {
	t.Setenv("S2A_SHIELD_MAX_HISTORY_BYTES", "1024")
	big := bytes.Repeat([]byte(`{"role":"user","content":"x"}`), 200)
	arr := []map[string]interface{}{}
	_ = json.Unmarshal([]byte("["+strings.Join(strings.Split(string(big), "}{"), "},{")+"]"), &arr)
	if len(arr) == 0 {
		t.Skip("skip construction")
	}
	trimmed, did := shieldTrimHistory(arr)
	if !did {
		t.Fatal("expected trim")
	}
	if b, err := json.Marshal(trimmed); err == nil && len(b) > 2048 {
		t.Fatalf("trim did not enforce limit: %d bytes", len(b))
	}
}

func TestShieldDisabledByDefault(t *testing.T) {
	if shieldEnabled() {
		t.Fatal("shield must be off by default (opt-in via S2A_SHIELD=1)")
	}
}
