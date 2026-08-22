package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type cyberTurnPruneTestCache struct {
	comboCacheAndStore
	plans map[string]CyberTurnPrunePlan
}

var _ CyberTurnPruneStore = (*cyberTurnPruneTestCache)(nil)

func (c *cyberTurnPruneTestCache) SetCyberTurnPrunePlan(_ context.Context, plan CyberTurnPrunePlan, _ time.Duration) error {
	if c.plans == nil {
		c.plans = make(map[string]CyberTurnPrunePlan)
	}
	c.plans[plan.FullTranscriptKey] = plan
	return nil
}

func (c *cyberTurnPruneTestCache) FindCyberTurnPrunePlans(_ context.Context, keys []string) ([]CyberTurnPrunePlan, error) {
	result := make([]CyberTurnPrunePlan, 0, 2)
	seen := make(map[string]struct{}, 2)
	for _, key := range keys {
		plan, ok := c.plans[key]
		if !ok {
			continue
		}
		if _, exists := seen[plan.FullTranscriptKey]; exists {
			continue
		}
		seen[plan.FullTranscriptKey] = struct{}{}
		result = append(result, plan)
	}
	return result, nil
}

func newCyberTurnPruneTestService() (*OpenAIGatewayService, *cyberTurnPruneTestCache) {
	cache := &cyberTurnPruneTestCache{}
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyCyberSessionBlockEnabled:    "true",
		SettingKeyCyberSessionBlockTTLSeconds: "60",
	}}}
	return &OpenAIGatewayService{cache: cache, settingService: settingSvc}, cache
}

func storeCyberTurnPrunePlan(t *testing.T, svc *OpenAIGatewayService, apiKeyID int64, body []byte) {
	t.Helper()
	plan := BuildCyberTurnPrunePlan(apiKeyID, body)
	require.NotEmpty(t, plan.FullTranscriptKey)
	keys := CyberSessionTranscriptBlockKeys(apiKeyID, body)
	require.NotEmpty(t, keys)
	svc.MarkCyberSessionBlockedWithPrunePlan(context.Background(), "scope", keys, plan)
}

func TestPruneBlockedCyberTurnResponsesKeepsCleanPrefixAndReplacement(t *testing.T) {
	const apiKeyID = int64(7)
	svc, _ := newCyberTurnPruneTestService()
	blocked := []byte(`{"model":"gpt-5","instructions":"style","input":[{"type":"message","role":"user","content":"setup"},{"type":"message","role":"assistant","content":"ready"},{"type":"message","role":"user","content":"trigger"}],"tools":[{"type":"function","name":"keep_tool"}]}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, blocked)

	continuation := []byte(`{"model":"gpt-5","instructions":"style","input":[{"type":"message","role":"user","content":"setup"},{"type":"message","role":"assistant","content":"ready"},{"type":"message","role":"user","content":"trigger"},{"type":"message","role":"assistant","content":"persisted cyber error"},{"type":"function_call_output","call_id":"call_from_trigger","output":"associated tool output"},{"type":"message","role":"user","content":"replacement"}],"tools":[{"type":"function","name":"keep_tool"}]}`)
	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, continuation)

	require.True(t, result.Matched)
	require.True(t, result.Changed)
	require.False(t, result.AwaitingReplacement)
	require.Equal(t, 1, result.PrunedTurns)
	require.NotEmpty(t, result.RecoverySessionID)
	require.Equal(t, "setup", gjson.GetBytes(result.Body, "input.0.content").String())
	require.Equal(t, "ready", gjson.GetBytes(result.Body, "input.1.content").String())
	require.Equal(t, "replacement", gjson.GetBytes(result.Body, "input.2.content").String())
	require.Len(t, gjson.GetBytes(result.Body, "input").Array(), 3)
	require.Equal(t, "keep_tool", gjson.GetBytes(result.Body, "tools.0.name").String())
	require.NotContains(t, string(result.Body), "trigger")
	require.NotContains(t, string(result.Body), "persisted cyber error")
	require.NotContains(t, string(result.Body), "associated tool output")
}

func TestPruneBlockedCyberTurnExactReplayWaitsForReplacement(t *testing.T) {
	const apiKeyID = int64(8)
	svc, _ := newCyberTurnPruneTestService()
	blocked := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, blocked)

	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, blocked)

	require.True(t, result.Matched)
	require.False(t, result.Changed)
	require.True(t, result.AwaitingReplacement)
	require.JSONEq(t, string(blocked), string(result.Body))
}

func TestPruneBlockedCyberTurnFirstTurnCanBeReplaced(t *testing.T) {
	const apiKeyID = int64(9)
	svc, _ := newCyberTurnPruneTestService()
	blocked := []byte(`{"input":[{"type":"message","role":"user","content":"trigger"}]}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, blocked)

	continuation := []byte(`{"input":[{"type":"message","role":"user","content":"trigger"},{"type":"message","role":"user","content":"replacement"}]}`)
	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, continuation)

	require.True(t, result.Changed)
	require.Equal(t, 1, result.PrunedTurns)
	require.Len(t, gjson.GetBytes(result.Body, "input").Array(), 1)
	require.Equal(t, "replacement", gjson.GetBytes(result.Body, "input.0.content").String())
}

func TestPruneBlockedCyberTurnsAppliesMultipleStoredCuts(t *testing.T) {
	const apiKeyID = int64(10)
	svc, _ := newCyberTurnPruneTestService()
	firstBlocked := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger-one"}]}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, firstBlocked)

	withSecondTurn := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger-one"},{"role":"user","content":"trigger-two"}]}`)
	firstRecovery := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, withSecondTurn)
	require.True(t, firstRecovery.Changed)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, firstRecovery.Body)

	continuation := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger-one"},{"role":"user","content":"trigger-two"},{"role":"user","content":"replacement"}]}`)
	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, continuation)

	require.True(t, result.Changed)
	require.Equal(t, 2, result.PrunedTurns)
	require.Len(t, gjson.GetBytes(result.Body, "messages").Array(), 3)
	require.Equal(t, "replacement", gjson.GetBytes(result.Body, "messages.2.content").String())
	require.NotContains(t, string(result.Body), "trigger-one")
	require.NotContains(t, string(result.Body), "trigger-two")
}

func TestPruneBlockedCyberTurnWebSocketEnvelope(t *testing.T) {
	const apiKeyID = int64(11)
	svc, _ := newCyberTurnPruneTestService()
	blocked := []byte(`{"type":"response.create","response":{"model":"gpt-5","input":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]},"event_id":"keep"}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, blocked)

	continuation := []byte(`{"type":"response.create","response":{"model":"gpt-5","input":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"},{"role":"user","content":"replacement"}]},"event_id":"keep"}`)
	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, continuation)

	require.True(t, result.Changed)
	require.Equal(t, "keep", gjson.GetBytes(result.Body, "event_id").String())
	require.Len(t, gjson.GetBytes(result.Body, "response.input").Array(), 3)
	require.Equal(t, "replacement", gjson.GetBytes(result.Body, "response.input.2.content").String())
}

func TestPruneBlockedCyberTurnScalarReplayIsQuarantined(t *testing.T) {
	const apiKeyID = int64(12)
	svc, _ := newCyberTurnPruneTestService()
	blocked := []byte(`{"input":"trigger"}`)
	storeCyberTurnPrunePlan(t, svc, apiKeyID, blocked)

	result := svc.PruneBlockedCyberTurns(context.Background(), apiKeyID, blocked)

	require.True(t, result.Matched)
	require.True(t, result.AwaitingReplacement)
	require.False(t, result.Changed)
}
