package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

const (
	cyberTurnPrunePlanVersion = 1
	maxCyberTurnPrunePasses   = 16
)

// CyberTurnPrunePlan identifies the exact transcript interval that produced an
// upstream cyber_policy response. FullTranscriptKey is the cumulative hash at
// the end of the rejected request; PreLatestUserKey is the cumulative hash
// immediately before its latest user turn. The latter is empty for a first
// turn without model-generated history.
type CyberTurnPrunePlan struct {
	Version           int    `json:"version"`
	FullTranscriptKey string `json:"full_transcript_key"`
	PreLatestUserKey  string `json:"pre_latest_user_key,omitempty"`
}

// CyberTurnPruneStore is an optional extension implemented by the production
// Redis gateway cache. Keeping it separate from CyberSessionBlockStore lets
// light-weight test caches retain the existing fail-open behavior.
type CyberTurnPruneStore interface {
	SetCyberTurnPrunePlan(ctx context.Context, plan CyberTurnPrunePlan, ttl time.Duration) error
	FindCyberTurnPrunePlans(ctx context.Context, transcriptKeys []string) ([]CyberTurnPrunePlan, error)
}

// CyberTurnPruneResult describes a transparent outbound-history recovery.
// AwaitingReplacement means the rejected request was replayed without a later
// user turn, so forwarding the shortened prefix would answer the wrong prompt.
type CyberTurnPruneResult struct {
	Body                []byte
	Changed             bool
	Matched             bool
	AwaitingReplacement bool
	PrunedTurns         int
	RecoverySessionID   string
}

// BuildCyberTurnPrunePlan records the latest user-turn boundary for a request
// that has just received cyber_policy. Invalid/non-transcript bodies produce
// an empty plan and keep the legacy session-reset behavior.
func BuildCyberTurnPrunePlan(apiKeyID int64, body []byte) CyberTurnPrunePlan {
	derived := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, body)
	if len(derived.lookupKeys) == 0 {
		return CyberTurnPrunePlan{}
	}
	return CyberTurnPrunePlan{
		Version:           cyberTurnPrunePlanVersion,
		FullTranscriptKey: derived.lookupKeys[len(derived.lookupKeys)-1],
		PreLatestUserKey:  derived.preLatestUserKey,
	}
}

func (p CyberTurnPrunePlan) valid() bool {
	return p.Version == cyberTurnPrunePlanVersion && strings.TrimSpace(p.FullTranscriptKey) != ""
}

// MarkCyberSessionBlockedWithPrunePlan stores the normal block keys and, when
// available, the exact rejected-turn boundary under the same TTL.
func (s *OpenAIGatewayService) MarkCyberSessionBlockedWithPrunePlan(
	ctx context.Context,
	scopeKey string,
	keys []string,
	plan CyberTurnPrunePlan,
) {
	if s == nil || len(keys) == 0 {
		return
	}
	enabled, ttl := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return
	}
	if err := store.SetCyberSessionBlocked(ctx, scopeKey, keys, ttl); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block write failed: err=%v", err)
		return
	}
	if !plan.valid() {
		return
	}
	pruneStore, ok := s.cache.(CyberTurnPruneStore)
	if !ok {
		return
	}
	if err := pruneStore.SetCyberTurnPrunePlan(ctx, plan, ttl); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber turn prune plan write failed: err=%v", err)
	}
}

// PruneBlockedCyberTurns removes every known rejected interval still present
// in the client-supplied full transcript. It never forwards an exact replay:
// at least one later user turn must exist after each rejected interval.
func (s *OpenAIGatewayService) PruneBlockedCyberTurns(ctx context.Context, apiKeyID int64, body []byte) CyberTurnPruneResult {
	result := CyberTurnPruneResult{Body: body}
	if s == nil || len(body) == 0 {
		return result
	}
	enabled, _ := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return result
	}
	store, ok := s.cache.(CyberTurnPruneStore)
	if !ok {
		return result
	}

	working := append([]byte(nil), body...)
	appliedFullKeys := make([]string, 0, 2)
	for pass := 0; pass < maxCyberTurnPrunePasses; pass++ {
		derived := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, working)
		if len(derived.lookupKeys) == 0 {
			break
		}
		plans, err := store.FindCyberTurnPrunePlans(ctx, derived.lookupKeys)
		if err != nil {
			logger.LegacyPrintf("service.openai_gateway", "cyber turn prune plan read failed: err=%v", err)
			break
		}
		if len(plans) == 0 {
			break
		}
		result.Matched = true
		if len(derived.lookupKeys) != len(derived.lookupItemIndexes) {
			// Scalar input has no separable history suffix. An exact replay must
			// wait for a genuinely new client message rather than forwarding the
			// same rejected text after an identifier reset.
			result.AwaitingReplacement = true
			result.Body = working
			return result
		}
		plan, fullItemIndex, preItemIndex, found := selectApplicableCyberTurnPrunePlan(plans, derived)
		if !found {
			// The rejected full prefix is present but its safe boundary fell
			// outside the bounded lookup window. Fail closed instead of guessing.
			result.AwaitingReplacement = true
			result.Body = working
			return result
		}

		items, ok := cyberTranscriptItems(working)
		if !ok || fullItemIndex < 0 || fullItemIndex >= len(items) || preItemIndex >= fullItemIndex {
			result.AwaitingReplacement = true
			result.Body = working
			return result
		}
		nextUserItemIndex, hasReplacement := cyberTranscriptNextUserTurnIndex(items, fullItemIndex)
		if !hasReplacement {
			result.AwaitingReplacement = true
			result.Body = working
			return result
		}

		// Everything between the rejected request and the next user message is
		// part of the rejected turn as observed by the local client (for example
		// a persisted error item, assistant refusal, or tool result). Remove that
		// associated suffix too so the outbound history is clean-prefix + rewrite.
		pruned, changed, err := pruneCyberTranscriptItemRange(working, preItemIndex+1, nextUserItemIndex-1)
		if err != nil || !changed {
			result.AwaitingReplacement = true
			result.Body = working
			return result
		}
		working = pruned
		result.Changed = true
		result.PrunedTurns++
		appliedFullKeys = append(appliedFullKeys, plan.FullTranscriptKey)
	}

	result.Body = working
	if len(appliedFullKeys) > 0 {
		result.RecoverySessionID = cyberTurnRecoverySessionID(apiKeyID, appliedFullKeys)
	}
	return result
}

func selectApplicableCyberTurnPrunePlan(
	plans []CyberTurnPrunePlan,
	derived openAICyberTranscriptBlockKeys,
) (CyberTurnPrunePlan, int, int, bool) {
	keyPositions := make(map[string]int, len(derived.lookupKeys))
	for i, key := range derived.lookupKeys {
		keyPositions[key] = i
	}
	for _, plan := range plans {
		if !plan.valid() {
			continue
		}
		fullPos, ok := keyPositions[plan.FullTranscriptKey]
		if !ok || fullPos >= len(derived.lookupItemIndexes) {
			continue
		}
		preItemIndex := -1
		if plan.PreLatestUserKey != "" {
			prePos, preOK := keyPositions[plan.PreLatestUserKey]
			if !preOK || prePos >= fullPos || prePos >= len(derived.lookupItemIndexes) {
				continue
			}
			preItemIndex = derived.lookupItemIndexes[prePos]
		}
		return plan, derived.lookupItemIndexes[fullPos], preItemIndex, true
	}
	return CyberTurnPrunePlan{}, 0, 0, false
}

func cyberTranscriptNextUserTurnIndex(items []json.RawMessage, fullItemIndex int) (int, bool) {
	for index := fullItemIndex + 1; index < len(items); index++ {
		raw := items[index]
		if openAICyberTranscriptItemStartsUserTurn(parseRawJSONView(raw)) {
			return index, true
		}
	}
	return 0, false
}

func cyberTranscriptItems(body []byte) ([]json.RawMessage, bool) {
	_, _, items, ok := decodeCyberTranscriptBody(body)
	return items, ok
}

func pruneCyberTranscriptItemRange(body []byte, start, end int) ([]byte, bool, error) {
	root, payload, items, ok := decodeCyberTranscriptBody(body)
	if !ok {
		return body, false, errors.New("cyber transcript sequence unavailable")
	}
	if start < 0 || end < start || end >= len(items) {
		return body, false, errors.New("invalid cyber transcript prune range")
	}
	kept := make([]json.RawMessage, 0, len(items)-(end-start+1))
	kept = append(kept, items[:start]...)
	kept = append(kept, items[end+1:]...)
	encodedItems, err := marshalCyberTurnJSON(kept)
	if err != nil {
		return body, false, err
	}

	field := "input"
	if _, exists := payload["messages"]; exists {
		field = "messages"
	}
	payload[field] = encodedItems

	eventType := ""
	_ = json.Unmarshal(root["type"], &eventType)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "response.") {
		if _, nested := root["response"]; nested {
			encodedPayload, marshalErr := marshalCyberTurnJSON(payload)
			if marshalErr != nil {
				return body, false, marshalErr
			}
			root["response"] = encodedPayload
		}
	}
	out, err := marshalCyberTurnJSON(root)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

func decodeCyberTranscriptBody(body []byte) (
	root map[string]json.RawMessage,
	payload map[string]json.RawMessage,
	items []json.RawMessage,
	ok bool,
) {
	if json.Unmarshal(body, &root) != nil || root == nil {
		return nil, nil, nil, false
	}
	payload = root
	eventType := ""
	_ = json.Unmarshal(root["type"], &eventType)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "response.") {
		var nested map[string]json.RawMessage
		if raw := root["response"]; len(raw) > 0 && json.Unmarshal(raw, &nested) == nil && nested != nil {
			payload = nested
		}
	}
	rawSequence := payload["input"]
	if rawMessages, exists := payload["messages"]; exists {
		rawSequence = rawMessages
	}
	if len(rawSequence) == 0 || json.Unmarshal(rawSequence, &items) != nil || items == nil {
		return root, payload, nil, false
	}
	return root, payload, items, true
}

func marshalCyberTurnJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func cyberTurnRecoverySessionID(apiKeyID int64, fullKeys []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("sub2api-shield-recovery:v1|"))
	_, _ = h.Write([]byte(strconv.FormatInt(apiKeyID, 10)))
	for _, key := range fullKeys {
		_, _ = h.Write([]byte("|"))
		_, _ = h.Write([]byte(key))
	}
	return "shield-recovery-" + hex.EncodeToString(h.Sum(nil))[:32]
}
