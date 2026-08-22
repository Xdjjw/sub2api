package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func shieldBodyForTest() []byte {
	return []byte(`{"model":"gpt-5.4","instructions":"You are Codex.","prompt_cache_key":"old-session-123","previous_response_id":"resp_prev_456","input":[{"role":"user","content":"继续任务"}]}`)
}

func decodeShieldBodyForTest(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestShieldTransformPreservesSessionIDsByDefault(t *testing.T) {
	out, changed := shieldTransformBody(shieldBodyForTest())
	if !changed {
		t.Fatal("expected instructions boost")
	}
	req := decodeShieldBodyForTest(t, out)
	if got := req["prompt_cache_key"]; got != "old-session-123" {
		t.Fatalf("prompt_cache_key changed: %v", got)
	}
	if got := req["previous_response_id"]; got != "resp_prev_456" {
		t.Fatalf("previous_response_id changed: %v", got)
	}
}

func TestShieldTransformStripsSessionIDsOnlyForExplicitReset(t *testing.T) {
	out, changed := shieldTransformBodyWithOptions(shieldBodyForTest(), shieldTransformOptions{resetSession: true})
	if !changed {
		t.Fatal("expected change")
	}
	req := decodeShieldBodyForTest(t, out)
	if _, exists := req["prompt_cache_key"]; exists {
		t.Fatal("prompt_cache_key should be stripped")
	}
	if _, exists := req["previous_response_id"]; exists {
		t.Fatal("previous_response_id should be stripped")
	}
}

func TestShieldTransformBoostsInstructions(t *testing.T) {
	out, _ := shieldTransformBody(shieldBodyForTest())
	req := decodeShieldBodyForTest(t, out)
	instructions, _ := req["instructions"].(string)
	if !strings.Contains(instructions, shieldInstructionsSentinel) {
		t.Fatal("instructions boost sentinel missing")
	}
}

func TestShieldTransformInjectsMissingEmptyAndNullInstructions(t *testing.T) {
	tests := map[string]string{
		"missing": `{"model":"gpt-5.4","input":[]}`,
		"empty":   `{"model":"gpt-5.4","instructions":"","input":[]}`,
		"null":    `{"model":"gpt-5.4","instructions":null,"input":[]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			out, changed := shieldTransformBody([]byte(body))
			if !changed {
				t.Fatal("expected instructions injection")
			}
			instructions, _ := decodeShieldBodyForTest(t, out)["instructions"].(string)
			if !strings.Contains(instructions, shieldInstructionsSentinel) {
				t.Fatalf("sentinel missing from %q", instructions)
			}
		})
	}
}

func TestShieldTransformSentinelIsIdempotentAndUnambiguous(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","instructions":"The user mentioned OUTPUT DISCIPLINE.","input":[]}`)
	first, changed := shieldTransformBody(body)
	if !changed {
		t.Fatal("title text must not masquerade as the sentinel")
	}
	second, changed := shieldTransformBody(first)
	if changed {
		t.Fatal("second transform should be a no-op")
	}
	if !bytes.Equal(first, second) {
		t.Fatal("idempotent transform changed bytes")
	}
	instructions, _ := decodeShieldBodyForTest(t, second)["instructions"].(string)
	if got := strings.Count(instructions, shieldInstructionsSentinel); got != 1 {
		t.Fatalf("sentinel count = %d, want 1", got)
	}

	userMention := []byte(`{"model":"gpt-5.4","input":"user text mentions ` + shieldInstructionsSentinel + `"}`)
	withUserMention, changed := shieldTransformBody(userMention)
	if !changed {
		t.Fatal("a sentinel outside instructions must not suppress the boost")
	}
	instructions, _ = decodeShieldBodyForTest(t, withUserMention)["instructions"].(string)
	if !strings.Contains(instructions, shieldInstructionsSentinel) {
		t.Fatal("instructions sentinel missing after user-text mention")
	}
}

func TestShieldTransformRecognizesProtocolLevelSentinel(t *testing.T) {
	tests := map[string]string{
		"chat":      `{"model":"gpt-5.4","messages":[{"role":"system","content":"` + shieldInstructionsSentinel + `"}]}`,
		"anthropic": `{"model":"claude","system":[{"type":"text","text":"` + shieldInstructionsSentinel + `"}],"messages":[]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			out, changed := shieldTransformBody([]byte(body))
			if changed || string(out) != body {
				t.Fatal("protocol-level sentinel should make the transport boost a no-op")
			}
			if _, exists := decodeShieldBodyForTest(t, out)["instructions"]; exists {
				t.Fatal("transport must not add top-level instructions")
			}
		})
	}
}

func TestShieldTransformDoesNotAddResponsesFieldToOtherProtocols(t *testing.T) {
	tests := map[string]string{
		"chat":      `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}]}`,
		"anthropic": `{"model":"claude","system":"Be concise.","messages":[{"role":"user","content":"hello"}]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			out, changed := shieldTransformBody([]byte(body))
			if changed || string(out) != body {
				t.Fatal("non-Responses payload should be left unchanged")
			}
			if _, exists := decodeShieldBodyForTest(t, out)["instructions"]; exists {
				t.Fatal("transport must not add Responses instructions to this protocol")
			}
		})
	}
}

func TestShieldTransformExplicitResetDoesNotDuplicateProtocolBoost(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","prompt_cache_key":"blocked","messages":[{"role":"system","content":"` + shieldInstructionsSentinel + `"}]}`)
	out, changed := shieldTransformBodyWithOptions(body, shieldTransformOptions{resetSession: true})
	if !changed {
		t.Fatal("session reset should change the body")
	}
	payload := decodeShieldBodyForTest(t, out)
	if _, exists := payload["prompt_cache_key"]; exists {
		t.Fatal("prompt_cache_key should be stripped")
	}
	if _, exists := payload["instructions"]; exists {
		t.Fatal("session reset must not duplicate a protocol-level boost")
	}
}

func TestShieldTransformPreservesNonStringInstructions(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","instructions":["provider-extension"],"input":[]}`)
	out, changed := shieldTransformBody(body)
	if changed {
		t.Fatal("non-string instructions should be preserved")
	}
	if !bytes.Equal(out, body) {
		t.Fatal("non-string instructions body changed")
	}
}

func TestShieldTransformPreservesJSONNull(t *testing.T) {
	body := []byte(`null`)
	out, changed := shieldTransformBody(body)
	if changed || !bytes.Equal(out, body) {
		t.Fatal("JSON null should be preserved")
	}
}

func TestShieldRewriteSynchronizesBodyMetadataAndGetBody(t *testing.T) {
	original := shieldBodyForTest()
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "Application/JSON; charset=utf-8")
	req.Header.Set("Content-Length", "1")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.TransferEncoding = []string{"chunked"}

	shieldRewriteRequest(req)
	written, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	replayedBody, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := io.ReadAll(replayedBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = replayedBody.Close()

	if !bytes.Equal(written, replayed) {
		t.Fatal("Body and GetBody differ")
	}
	if req.ContentLength != int64(len(written)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(written))
	}
	if got := req.Header.Get("Content-Length"); got != strconv.Itoa(len(written)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(written))
	}
	if len(req.TransferEncoding) != 0 || req.Header.Get("Transfer-Encoding") != "" {
		t.Fatal("Transfer-Encoding should be cleared for the buffered request")
	}
	reqBody := decodeShieldBodyForTest(t, written)
	if got := reqBody["prompt_cache_key"]; got != "old-session-123" {
		t.Fatalf("normal rewrite stripped session: %v", got)
	}
}

func TestShieldRewriteRestoresUnchangedBodyAndGetBody(t *testing.T) {
	original := []byte(`{"not-json"`)
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	shieldRewriteRequest(req)
	assertShieldRequestBodyReplay(t, req, original)
}

func TestShieldRewriteSkipsEmbeddingsInputShape(t *testing.T) {
	original := []byte(`{"model":"text-embedding-3-small","input":["hello"]}`)
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/embeddings", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	shieldRewriteRequest(req)
	assertShieldRequestBodyReplay(t, req, original)
}

func TestShieldRewriteDoesNotDuplicateBridgedDeveloperInstruction(t *testing.T) {
	original := []byte(`{"model":"gpt-5","input":[{"role":"developer","content":[{"type":"input_text","text":"` + shieldInstructionsSentinel + `"}]},{"role":"user","content":"hello"}]}`)
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	shieldRewriteRequest(req)
	assertShieldRequestBodyReplay(t, req, original)
}

func TestShieldRewriteReadAllFailureLeavesReplayableOriginal(t *testing.T) {
	original := shieldBodyForTest()
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	originalLength := req.ContentLength
	originalHeaderLength := req.Header.Get("Content-Length")

	getBodyCalls := 0
	originalGetBody := req.GetBody
	req.GetBody = func() (io.ReadCloser, error) {
		getBodyCalls++
		if getBodyCalls == 1 {
			return io.NopCloser(&shieldFailingReader{data: original, failAfter: 17}), nil
		}
		return originalGetBody()
	}

	shieldRewriteRequest(req)
	if req.ContentLength != originalLength || req.Header.Get("Content-Length") != originalHeaderLength {
		t.Fatal("read failure changed length metadata")
	}
	assertShieldRequestBodyReplay(t, req, original)
}

func TestShieldRewriteReadAllFailureWithoutGetBodyRestoresConsumedPrefix(t *testing.T) {
	original := shieldBodyForTest()
	body := &shieldFailOnceReadCloser{data: original, failAfter: 23}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", body)
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = nil
	req.ContentLength = int64(len(original))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(original)))

	shieldRewriteRequest(req)
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored body differs: got %d bytes, want %d", len(restored), len(original))
	}
	if req.GetBody != nil {
		t.Fatal("failed read without an original GetBody must not invent an unsafe replay factory")
	}
	if req.ContentLength != int64(len(original)) || req.Header.Get("Content-Length") != strconv.Itoa(len(original)) {
		t.Fatal("read failure changed length metadata")
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

func assertShieldRequestBodyReplay(t *testing.T, req *http.Request, want []byte) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("Body differs: got %q, want %q", body, want)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody is nil")
	}
	replayBody, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replay, err := io.ReadAll(replayBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = replayBody.Close()
	if !bytes.Equal(replay, want) {
		t.Fatalf("GetBody differs: got %q, want %q", replay, want)
	}
}

type shieldFailingReader struct {
	data      []byte
	offset    int
	failAfter int
}

func (r *shieldFailingReader) Read(p []byte) (int, error) {
	if r.offset >= r.failAfter {
		return 0, errors.New("injected read failure")
	}
	limit := r.failAfter - r.offset
	if len(p) > limit {
		p = p[:limit]
	}
	n := copy(p, r.data[r.offset:r.failAfter])
	r.offset += n
	if r.offset >= r.failAfter {
		return n, errors.New("injected read failure")
	}
	return n, nil
}

type shieldFailOnceReadCloser struct {
	data      []byte
	offset    int
	failAfter int
	failed    bool
}

func (r *shieldFailOnceReadCloser) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	if !r.failed {
		limit := r.failAfter - r.offset
		if limit < 0 {
			limit = 0
		}
		if len(p) > limit {
			p = p[:limit]
		}
		n := copy(p, r.data[r.offset:r.offset+limit])
		r.offset += n
		r.failed = true
		return n, errors.New("injected transient read failure")
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *shieldFailOnceReadCloser) Close() error { return nil }
