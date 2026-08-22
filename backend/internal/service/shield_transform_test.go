package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestApplyShieldToResponsesBody_MissingInstructionsAndIdempotent(t *testing.T) {
	body := []byte(`{"model":"gpt-5","input":"hello","prompt_cache_key":"keep"}`)
	out, changed := ApplyShieldToResponsesBody(body)
	require.True(t, changed)
	require.Contains(t, gjson.GetBytes(out, "instructions").String(), ShieldInstructionsSentinel)
	require.Equal(t, "keep", gjson.GetBytes(out, "prompt_cache_key").String())

	again, changed := ApplyShieldToResponsesBody(out)
	require.False(t, changed)
	require.Equal(t, string(out), string(again))
}

func TestShieldTransforms_NonObjectPayloadFailsOpen(t *testing.T) {
	for name, transform := range map[string]func([]byte) ([]byte, bool){
		"responses": ApplyShieldToResponsesBody,
		"chat":      ApplyShieldToChatCompletionsBody,
		"anthropic": ApplyShieldToAnthropicMessagesBody,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				out, changed := transform([]byte(`null`))
				require.False(t, changed)
				require.Equal(t, `null`, string(out))
			})
		})
	}
}

func TestApplyShieldToChatCompletionsBody_PrependsSystemMessage(t *testing.T) {
	body := []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"hello"}]}`)
	out, changed := ApplyShieldToChatCompletionsBody(body)
	require.True(t, changed)
	require.Equal(t, "system", gjson.GetBytes(out, "messages.0.role").String())
	require.Contains(t, gjson.GetBytes(out, "messages.0.content").String(), ShieldInstructionsSentinel)
	require.Equal(t, "user", gjson.GetBytes(out, "messages.1.role").String())
}

func TestApplyShieldToChatCompletionsBody_AppendsExistingDeveloperContentPart(t *testing.T) {
	body := []byte(`{"model":"gpt-5","messages":[{"role":"developer","content":[{"type":"text","text":"existing"}]},{"role":"user","content":"hello"}]}`)
	out, changed := ApplyShieldToChatCompletionsBody(body)
	require.True(t, changed)
	require.Equal(t, 2, int(gjson.GetBytes(out, "messages.#").Int()))
	require.Equal(t, "developer", gjson.GetBytes(out, "messages.0.role").String())
	require.Equal(t, "existing", gjson.GetBytes(out, "messages.0.content.0.text").String())
	require.Equal(t, "text", gjson.GetBytes(out, "messages.0.content.1.type").String())
	require.Contains(t, gjson.GetBytes(out, "messages.0.content.1.text").String(), ShieldInstructionsSentinel)
	require.Equal(t, "user", gjson.GetBytes(out, "messages.1.role").String())

	again, changed := ApplyShieldToChatCompletionsBody(out)
	require.False(t, changed)
	require.Equal(t, string(out), string(again))
}

func TestApplyShieldToChatCompletionsBody_RecognizesSentinelInLaterInstructionMessage(t *testing.T) {
	body := []byte(`{"model":"gpt-5","messages":[{"role":"system","content":"existing"},{"role":"developer","content":[{"type":"text","text":"` + ShieldInstructionsSentinel + `"}]},{"role":"user","content":"hello"}]}`)
	out, changed := ApplyShieldToChatCompletionsBody(body)
	require.False(t, changed)
	require.Equal(t, string(body), string(out))
}

func TestApplyShieldToChatCompletionsBody_UsesResponsesSemanticsForCursorShape(t *testing.T) {
	body := []byte(`{"model":"gpt-5","input":[{"role":"user","content":"hello"}]}`)
	out, changed := ApplyShieldToChatCompletionsBody(body)
	require.True(t, changed)
	require.Contains(t, gjson.GetBytes(out, "instructions").String(), ShieldInstructionsSentinel)
	require.Equal(t, "user", gjson.GetBytes(out, "input.0.role").String())
}

func TestApplyShieldToResponsesBody_RecognizesBridgeInstructionInInput(t *testing.T) {
	body := []byte(`{"model":"gpt-5","input":[{"role":"developer","content":[{"type":"input_text","text":"` + ShieldInstructionsSentinel + `"}]},{"role":"user","content":"hello"}]}`)
	out, changed := ApplyShieldToResponsesBody(body)
	require.False(t, changed)
	require.Equal(t, string(body), string(out))
	require.False(t, gjson.GetBytes(out, "instructions").Exists())
}

func TestApplyShieldToAnthropicMessagesBody_AppendsContentBlock(t *testing.T) {
	body := []byte(`{"model":"claude","system":[{"type":"text","text":"existing"}],"messages":[]}`)
	out, changed := ApplyShieldToAnthropicMessagesBody(body)
	require.True(t, changed)
	require.Equal(t, "existing", gjson.GetBytes(out, "system.0.text").String())
	require.Contains(t, gjson.GetBytes(out, "system.1.text").String(), ShieldInstructionsSentinel)

	_, changed = ApplyShieldToAnthropicMessagesBody(out)
	require.False(t, changed)
}
