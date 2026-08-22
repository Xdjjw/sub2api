package repository

// sub2api 版 cyber-shield。
// 能力：instructions 输出纪律注入 + 显式会话重置（配合 handler 层的 cyber 封禁绕过）。
// 开关：分组级 shield_enabled 由网关语义层处理；本 transport safety net
// 仅响应 S2A_SHIELD=1（默认关）的 OpenAI profile 请求。

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

var shieldEnabledFlag atomic.Bool

func init() {
	if v := os.Getenv("S2A_SHIELD"); v == "1" || strings.EqualFold(v, "true") || v == "on" {
		shieldEnabledFlag.Store(true)
		log.Printf("[shield] sub2api shield enabled (S2A_SHIELD=1)")
	}
}

func shieldEnabled() bool { return shieldEnabledFlag.Load() }

// shieldInstructionsSentinel 是 boost 的精确幂等标记。不使用可能出现在
// 普通提示词中的标题文字判断，避免伪命中跳过注入。
const shieldInstructionsSentinel = service.ShieldInstructionsSentinel

type shieldTransformOptions struct {
	// resetSession 只能由已确认的 cyber 会话重置路径显式打开。
	// 普通 Shield 请求必须保留粘性和 Responses 续链语义。
	resetSession bool
}

type shieldRequestProtocol int

const (
	shieldProtocolNone shieldRequestProtocol = iota
	shieldProtocolAuto
	shieldProtocolResponses
	shieldProtocolChatCompletions
	shieldProtocolAnthropicMessages
)

// shieldRewriteRequest 在 Do() 入口对 JSON 请求体执行常规 shield 变换。
// 常规变换只注入 boost，不会重置会话。
func shieldRewriteRequest(req *http.Request) {
	shieldRewriteRequestWithOptions(req, shieldTransformOptions{})
}

// shieldRewriteRequestWithOptions 将可能破坏续链的会话重置与常规 boost 分离。
// 读取或变换失败时保留原请求语义，Shield 永不阻断业务。
func shieldRewriteRequestWithOptions(req *http.Request, options shieldTransformOptions) {
	if req == nil || req.Method != http.MethodPost || req.Body == nil {
		return
	}
	protocol := shieldProtocolForRequest(req)
	if protocol == shieldProtocolNone {
		return
	}
	ct := req.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "application/json") {
		return
	}

	body, err := shieldReadRequestBody(req)
	if err != nil {
		return
	}

	transformed, changed := shieldTransformBodyForProtocol(body, options, protocol)
	if !changed {
		shieldSetRequestBody(req, body)
		return
	}
	shieldSetRequestBody(req, transformed)
	log.Printf("[shield] transformed request: %d -> %d bytes", len(body), len(transformed))
}

// shieldReadRequestBody 优先读 GetBody 产生的副本，这样读取失败不会消费
// 待发送的 Body。没有 GetBody 时，失败后用“已读前缀 + 原 reader 剩余部分”
// 恢复请求，避免 io.ReadAll 吞掉已成功读取的字节。
func shieldReadRequestBody(req *http.Request) ([]byte, error) {
	source := req.Body
	readingClone := false
	if req.GetBody != nil {
		clone, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		if clone == nil {
			return nil, io.ErrUnexpectedEOF
		}
		source = clone
		readingClone = true
	}

	body, err := io.ReadAll(source)
	if readingClone {
		_ = source.Close()
	}
	if err != nil {
		if !readingClone {
			req.Body = &shieldReplayReadCloser{
				Reader: io.MultiReader(bytes.NewReader(body), source),
				Closer: source,
			}
		}
		return nil, err
	}
	return body, nil
}

type shieldReplayReadCloser struct {
	io.Reader
	io.Closer
}

// shieldSetRequestBody 将 Body 及 net/http 可能用于重定向/重放的所有元数据
// 统一到同一份不可变字节快照。
func shieldSetRequestBody(req *http.Request, body []byte) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	snapshot := bytes.Clone(body)
	req.Body = io.NopCloser(bytes.NewReader(snapshot))
	req.ContentLength = int64(len(snapshot))
	req.TransferEncoding = nil
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(snapshot)))
	req.Header.Del("Transfer-Encoding")
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(snapshot)), nil
	}
}

// shieldTransformBody 执行常规 boost。它特意保留 prompt_cache_key 和
// previous_response_id，避免每个 Shield 请求都被错当成新会话。
func shieldTransformBody(body []byte) ([]byte, bool) {
	return shieldTransformBodyWithOptions(body, shieldTransformOptions{})
}

// shieldTransformBodyWithOptions 仅在 options.resetSession 为 true 时剥离会话标识。
func shieldTransformBodyWithOptions(body []byte, options shieldTransformOptions) ([]byte, bool) {
	return shieldTransformBodyForProtocol(body, options, shieldProtocolAuto)
}

func shieldTransformBodyForProtocol(body []byte, options shieldTransformOptions, protocol shieldRequestProtocol) ([]byte, bool) {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body, false
	}
	if req == nil {
		return body, false
	}
	changed := false
	if options.resetSession {
		if _, exists := req["prompt_cache_key"]; exists {
			delete(req, "prompt_cache_key")
			changed = true
		}
		if _, exists := req["previous_response_id"]; exists {
			delete(req, "previous_response_id")
			changed = true
		}
	}

	working := body
	if changed {
		var err error
		working, err = json.Marshal(req)
		if err != nil {
			return body, false
		}
	}

	if protocol == shieldProtocolAuto {
		_, hasInput := req["input"]
		_, hasInstructions := req["instructions"]
		if !hasInput && !hasInstructions {
			return working, changed
		}
		protocol = shieldProtocolResponses
	}

	var transformed []byte
	var injected bool
	switch protocol {
	case shieldProtocolResponses:
		transformed, injected = service.ApplyShieldToResponsesBody(working)
	case shieldProtocolChatCompletions:
		transformed, injected = service.ApplyShieldToChatCompletionsBody(working)
	case shieldProtocolAnthropicMessages:
		transformed, injected = service.ApplyShieldToAnthropicMessagesBody(working)
	default:
		return working, changed
	}
	if injected {
		return transformed, true
	}
	return working, changed
}

func shieldProtocolForRequest(req *http.Request) shieldRequestProtocol {
	if req == nil || req.URL == nil {
		return shieldProtocolNone
	}
	path := strings.ToLower(strings.TrimSpace(req.URL.Path))
	switch {
	case shieldPathHasEndpoint(path, "/responses/input_tokens"):
		return shieldProtocolNone
	case shieldPathHasEndpoint(path, "/chat/completions"):
		return shieldProtocolChatCompletions
	case shieldPathHasEndpoint(path, "/messages"):
		return shieldProtocolAnthropicMessages
	case shieldPathHasEndpoint(path, "/responses"):
		return shieldProtocolResponses
	default:
		return shieldProtocolNone
	}
}

func shieldPathHasEndpoint(path, endpoint string) bool {
	for start := 0; ; {
		idx := strings.Index(path[start:], endpoint)
		if idx < 0 {
			return false
		}
		idx += start
		after := idx + len(endpoint)
		if after == len(path) || path[after] == '/' {
			return true
		}
		start = after
	}
}

// shieldTouch 请求计数。
var shieldReqCount atomic.Int64

func shieldTouch(req *http.Request) {
	n := shieldReqCount.Add(1)
	if n%50 == 1 {
		log.Printf("[shield] requests seen: %d (last: %s %s)", n, req.Method, req.URL.Path)
	}
}
