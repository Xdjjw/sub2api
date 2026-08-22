package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// newTestGinContext builds a bare gin.Context backed by an httptest recorder.
func newTestGinContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c
}

// TestRecordCyberPolicyIfMarked_NoMark verifies that when no cyber mark is set,
// the function returns immediately and does NOT set the recorded flag.
func TestRecordCyberPolicyIfMarked_NoMark(t *testing.T) {
	c := newTestGinContext()
	h := &OpenAIGatewayHandler{}

	h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", true, nil, service.ChannelUsageFields{}, "")

	// Flag must NOT be set when there was no mark.
	require.False(t, c.GetBool(cyberPolicyRecordedKey),
		"cyberPolicyRecordedKey must remain false when no cyber mark is present")
}

// TestRecordCyberPolicyIfMarked_WithMark verifies that:
//  1. When a cyber mark is present, the recorded flag is set (guard activated).
//  2. A second call is a no-op (idempotent guard).
//  3. Nil services do not panic.
func TestRecordCyberPolicyIfMarked_WithMark(t *testing.T) {
	c := newTestGinContext()
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{
		Message:        "flagged",
		Body:           `{"error":{"code":"cyber_policy"}}`,
		UpstreamStatus: 400,
	})

	h := &OpenAIGatewayHandler{} // nil services — must not panic

	// First call: should set the flag.
	require.NotPanics(t, func() {
		h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", true, nil, service.ChannelUsageFields{}, "")
	})
	require.True(t, c.GetBool(cyberPolicyRecordedKey),
		"cyberPolicyRecordedKey must be true after first call with a mark")

	// Second call: flag already set — must be a no-op (idempotent).
	require.NotPanics(t, func() {
		h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", false, nil, service.ChannelUsageFields{}, "")
	})
	// Flag should still be true (not toggled or cleared).
	require.True(t, c.GetBool(cyberPolicyRecordedKey),
		"cyberPolicyRecordedKey must remain true after second call (guard)")
}

// TestRecordCyberPolicyIfMarked_ForwardSuccessSkipsUsageLog verifies the semantic:
// when forwardErrored=false the function still sets the guard flag (mark present),
// but the cyber usage row is NOT requested (only RecordCyberPolicyEvent fires).
// Since services are nil here we only verify the guard flag and no panic.
func TestRecordCyberPolicyIfMarked_ForwardSuccessSkipsUsageLog(t *testing.T) {
	c := newTestGinContext()
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{
		Message:        "flagged",
		UpstreamStatus: 200,
	})

	h := &OpenAIGatewayHandler{}

	require.NotPanics(t, func() {
		h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", false /* forwardErrored=false */, nil, service.ChannelUsageFields{}, "")
	})
	require.True(t, c.GetBool(cyberPolicyRecordedKey))
}

// TestClearCyberPolicyTurnState verifies F1 at the handler level: after a turn
// is finalized, both the mark and the recorded guard are reset so the next WS
// turn detects/records independently.
func TestClearCyberPolicyTurnState(t *testing.T) {
	c := newTestGinContext()
	h := &OpenAIGatewayHandler{}

	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{Message: "turn1", UpstreamStatus: 200})
	h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", false, nil, service.ChannelUsageFields{}, "")
	require.True(t, c.GetBool(cyberPolicyRecordedKey))

	clearCyberPolicyTurnState(c)
	require.Nil(t, service.GetOpsCyberPolicy(c))
	require.False(t, c.GetBool(cyberPolicyRecordedKey))

	// turn2: a fresh cyber hit must be recordable again.
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{Message: "turn2", UpstreamStatus: 200})
	h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", false, nil, service.ChannelUsageFields{}, "")
	require.True(t, c.GetBool(cyberPolicyRecordedKey))
	require.Equal(t, "turn2", service.GetOpsCyberPolicy(c).Message)
}

// TestBuildCyberSessionBlockedOpsEntry verifies the locally-rejected request is
// auditable: 403 / phase=request / type=cyber_policy_session_blocked — distinct
// from upstream cyber_policy hits, and it must NOT touch moderation/violation.
func TestBuildCyberSessionBlockedOpsEntry(t *testing.T) {
	entry := buildCyberSessionBlockedOpsEntry(cyberPolicyOpsErrorMeta{
		RequestID: "req-9", Model: "gpt-5", RequestPath: "/openai/v1/responses",
	})
	require.Equal(t, 403, entry.StatusCode)
	require.Equal(t, "cyber_policy_session_blocked", entry.ErrorType)
	require.Equal(t, "request", entry.ErrorPhase)
	require.True(t, entry.IsBusinessLimited)
	require.Equal(t, "gateway_local", entry.ErrorSource)
	require.Equal(t, "platform", entry.ErrorOwner)
	require.Empty(t, entry.ErrorBody, "no session block key → ErrorBody must be empty")

	entryWithKey := buildCyberSessionBlockedOpsEntry(cyberPolicyOpsErrorMeta{
		RequestID: "req-9", Model: "gpt-5", RequestPath: "/openai/v1/responses",
		SessionBlockKey: "abc123",
	})
	require.Equal(t, "session_block_key=abc123", entryWithKey.ErrorBody)
}

// TestRejectIfCyberSessionBlocked_FailOpen verifies fail-open paths: nil handler
// services, no explicit session signal, and (implicitly) disabled switch all
// pass the request through.
func TestCheckCyberSessionBlock_FailOpen(t *testing.T) {
	c := newTestGinContext()
	c.Request = httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(`{}`))

	h := &OpenAIGatewayHandler{}
	action, keyValue := h.checkCyberSessionBlock(c, nil, []byte(`{}`), "gpt-5", cyberBlockFormatResponses)
	require.Equal(t, cyberSessionBlockAllowed, action, "nil apiKey → pass")
	require.Empty(t, keyValue)

	h2 := &OpenAIGatewayHandler{gatewayService: nil}
	key := &service.APIKey{ID: 1}
	action, keyValue = h2.checkCyberSessionBlock(c, key, []byte(`{}`), "gpt-5", cyberBlockFormatResponses)
	require.Equal(t, cyberSessionBlockAllowed, action, "nil gateway service → pass")
	require.Empty(t, keyValue)

	h3 := &OpenAIGatewayHandler{gatewayService: &service.OpenAIGatewayService{}}
	action, keyValue = h3.checkCyberSessionBlock(nil, key, []byte(`{}`), "gpt-5", cyberBlockFormatResponses)
	require.Equal(t, cyberSessionBlockAllowed, action, "nil context → pass")
	require.Empty(t, keyValue)
}

func TestStripOpenAISessionIdentifiers_RemovesAllSchedulingSignals(t *testing.T) {
	c := newTestGinContext()
	c.Request = httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(`{}`))
	for _, header := range []string{
		"session_id", "conversation_id", "X-Session-Affinity", "X-Session-Id",
		"X-OpenCode-Session", "X-Conversation-ID", "X-Grok-Conv-Id",
		"X-Codex-Turn-State", "X-Codex-Turn-Metadata", "Session-Id", "Thread-Id", "X-Codex-Window-Id",
	} {
		c.Request.Header.Set(header, "sticky")
	}

	stripOpenAISessionIdentifiers(c)

	for _, header := range []string{
		"session_id", "conversation_id", "X-Session-Affinity", "X-Session-Id",
		"X-OpenCode-Session", "X-Conversation-ID", "X-Grok-Conv-Id",
		"X-Codex-Turn-State", "X-Codex-Turn-Metadata", "Session-Id", "Thread-Id", "X-Codex-Window-Id",
	} {
		require.Empty(t, c.Request.Header.Get(header), header)
	}
}

func TestStripOpenAISessionIdentifiersFromBody_PreservesUnrelatedMetadata(t *testing.T) {
	body := []byte(`{"model":"gpt-5","prompt_cache_key":"old","previous_response_id":"resp_old","metadata":{"user_id":"sticky","trace":"keep"},"client_metadata":{"session_id":"body-session","thread_id":"thread","turn_id":"turn","window_id":"window","x-codex-turn-metadata":"old","installation_id":"keep-install"},"input":"hello"}`)

	out, changed := stripOpenAISessionIdentifiersFromBody(body)

	require.True(t, changed)
	require.False(t, gjson.GetBytes(out, "prompt_cache_key").Exists())
	require.False(t, gjson.GetBytes(out, "previous_response_id").Exists())
	require.False(t, gjson.GetBytes(out, "metadata.user_id").Exists())
	require.Equal(t, "keep", gjson.GetBytes(out, "metadata.trace").String())
	require.False(t, gjson.GetBytes(out, "client_metadata.session_id").Exists())
	require.False(t, gjson.GetBytes(out, "client_metadata.thread_id").Exists())
	require.False(t, gjson.GetBytes(out, "client_metadata.turn_id").Exists())
	require.False(t, gjson.GetBytes(out, "client_metadata.window_id").Exists())
	require.False(t, gjson.GetBytes(out, "client_metadata.x-codex-turn-metadata").Exists())
	require.Equal(t, "keep-install", gjson.GetBytes(out, "client_metadata.installation_id").String())
	require.Equal(t, "hello", gjson.GetBytes(out, "input").String())
}

func TestBindShieldRecoverySession_BindsHeadersAndResponsesBody(t *testing.T) {
	c := newTestGinContext()
	c.Request = httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(`{}`))
	body := []byte(`{"model":"gpt-5","prompt_cache_key":"old","input":[{"role":"user","content":"replacement"}],"metadata":{"trace":"keep"}}`)

	out := bindShieldRecoverySession(c, body, " shield-recovery-abc ", cyberBlockFormatResponses)

	require.Equal(t, "shield-recovery-abc", c.Request.Header.Get("session_id"))
	require.Equal(t, "shield-recovery-abc", c.Request.Header.Get("conversation_id"))
	require.Equal(t, "shield-recovery-abc", gjson.GetBytes(out, "prompt_cache_key").String())
	require.Equal(t, "replacement", gjson.GetBytes(out, "input.0.content").String())
	require.Equal(t, "keep", gjson.GetBytes(out, "metadata.trace").String())
}

func TestBindShieldRecoverySession_BindsWebSocketEnvelope(t *testing.T) {
	c := newTestGinContext()
	c.Request = httptest.NewRequest("GET", "/openai/v1/responses", nil)
	body := []byte(`{"type":"response.create","event_id":"evt_keep","response":{"model":"gpt-5","prompt_cache_key":"old","input":[{"role":"user","content":"replacement"}]}}`)

	out := bindShieldRecoverySession(c, body, "shield-recovery-ws", cyberBlockFormatResponses)

	require.Equal(t, "shield-recovery-ws", gjson.GetBytes(out, "response.prompt_cache_key").String())
	require.Equal(t, "evt_keep", gjson.GetBytes(out, "event_id").String())
	require.Equal(t, "replacement", gjson.GetBytes(out, "response.input.0.content").String())
}

func TestBindShieldRecoverySession_ChatOnlyBindsHeaders(t *testing.T) {
	c := newTestGinContext()
	c.Request = httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`))
	body := []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"replacement"}]}`)

	out := bindShieldRecoverySession(c, body, "shield-recovery-chat", cyberBlockFormatChat)

	require.Equal(t, string(body), string(out))
	require.Equal(t, "shield-recovery-chat", c.Request.Header.Get("session_id"))
	require.Equal(t, "shield-recovery-chat", c.Request.Header.Get("conversation_id"))
}

func TestWriteCyberTurnQuarantined_OpenAIEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(`{}`))

	h := &OpenAIGatewayHandler{}
	h.writeCyberTurnQuarantined(c, &service.APIKey{ID: 7}, "gpt-5", cyberBlockFormatResponses, "blocked-key")

	require.Equal(t, 403, w.Code)
	require.Equal(t, "permission_error", gjson.Get(w.Body.String(), "error.type").String())
	require.Equal(t, "cyber_turn_quarantined", gjson.Get(w.Body.String(), "error.code").String())
	require.Contains(t, gjson.Get(w.Body.String(), "error.message").String(), "重新表述")
}

func TestWriteCyberTurnQuarantined_AnthropicEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(`{}`))

	h := &OpenAIGatewayHandler{}
	h.writeCyberTurnQuarantined(c, &service.APIKey{ID: 8}, "claude", cyberBlockFormatAnthropic, "blocked-key")

	require.Equal(t, 403, w.Code)
	require.Equal(t, "error", gjson.Get(w.Body.String(), "type").String())
	require.Equal(t, "permission_error", gjson.Get(w.Body.String(), "error.type").String())
	require.False(t, gjson.Get(w.Body.String(), "error.code").Exists())
	require.Contains(t, gjson.Get(w.Body.String(), "error.message").String(), "重新表述")
}

func TestBuildCyberSessionBlockWritePlanCombinesExplicitAndTranscriptKeys(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`)
	c := newTestGinContext()
	c.Request = httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(string(body)))
	c.Request.RemoteAddr = "203.0.113.44:12345"
	c.Request.Header.Set("User-Agent", "client/1.2.3")

	plan := buildCyberSessionBlockWritePlan(7, c, body)
	require.Len(t, plan.keys, 2)
	require.NotEmpty(t, plan.scopeKey)

	c.Request.Header.Set("session_id", "sess-explicit")
	plan = buildCyberSessionBlockWritePlan(7, c, body)
	require.Len(t, plan.keys, 3)
	require.NotEmpty(t, plan.scopeKey)
}

// TestRecordCyberPolicyIfMarked_BlockKeyPlumbed verifies the 6th param is
// accepted and a non-empty key with nil gateway service does not panic
// (write-side guards live in the service layer).
func TestRecordCyberPolicyIfMarked_BlockKeyPlumbed(t *testing.T) {
	c := newTestGinContext()
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{Message: "x", UpstreamStatus: 400})
	h := &OpenAIGatewayHandler{}
	require.NotPanics(t, func() {
		h.recordCyberPolicyIfMarked(c, nil, nil, nil, "gpt-5", true, []byte(`{"input":"deadbeef"}`), service.ChannelUsageFields{}, "")
	})
}

// TestBuildCyberPolicyOpsErrorEntry_StatusCode verifies F6: the ops error log
// records the status the codex client actually received (400 non-stream / 200 stream),
// not a hardcoded 403.
func TestBuildCyberPolicyOpsErrorEntry_StatusCode(t *testing.T) {
	for _, tc := range []struct {
		name           string
		upstreamStatus int
	}{
		{"non_stream_400", 400},
		{"stream_200", 200},
		{"zero_value", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mark := &service.CyberPolicyMark{
				Code:           "cyber_policy",
				Message:        "blocked",
				UpstreamStatus: tc.upstreamStatus,
			}
			entry := buildCyberPolicyOpsErrorEntry(cyberPolicyOpsErrorMeta{
				RequestID: "req-1", Model: "gpt-5", RequestPath: "/openai/v1/responses",
			}, mark)
			require.Equal(t, tc.upstreamStatus, entry.StatusCode)
			require.Equal(t, "cyber_policy", entry.ErrorType)
			require.Equal(t, "request", entry.ErrorPhase)
		})
	}
}
