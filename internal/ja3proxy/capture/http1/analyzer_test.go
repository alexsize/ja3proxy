package http1

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAnalyzerPreservesHeaderOrderAndSpellingWithoutValues(t *testing.T) {
	a := New("client_to_upstream", 1024)
	partA := []byte("GET /items HTTP/1.1\r\nHost: Example.test\r\nX-Custom: secret")
	if got := a.Observe(partA); len(got) != 0 {
		t.Fatalf("early messages = %+v", got)
	}
	message := a.Observe([]byte("\r\nContent-Length: 0\r\n\r\n"))
	if len(message) != 1 {
		t.Fatalf("messages = %d", len(message))
	}
	got := message[0]
	if got.Kind != "request" || got.Method != "GET" || got.RequestTarget != "/items" || got.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("request = %+v", got)
	}
	if !bytes.Equal([]byte(got.HeaderOrder[0]), []byte("Host")) || got.OriginalHeaderNames[1] != "X-Custom" {
		t.Fatalf("header order/spelling = %+v / %+v", got.HeaderOrder, got.OriginalHeaderNames)
	}
	if len(got.Headers) != 3 || got.Headers[1].ValueSHA256 == "" || got.Headers[1].ValueSHA256 == "secret" {
		t.Fatalf("privacy-safe headers = %+v", got.Headers)
	}
}

func TestAnalyzerExtractsUnverifiedApplicationVersionWithoutRetainingUserAgent(t *testing.T) {
	a := New("client_to_upstream", 1024)
	messages := a.Observe([]byte("GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: ExampleApp/4.2.1 (iOS)\r\n\r\n"))
	if len(messages) != 1 || len(messages[0].VersionEvidence) != 1 {
		t.Fatalf("messages = %+v", messages)
	}
	evidence := messages[0].VersionEvidence[0]
	if evidence.Product != "ExampleApp" || evidence.Version != "4.2.1" || evidence.Source != "http_user_agent" || evidence.Confidence != "low" || evidence.Status != "unverified" {
		t.Fatalf("version evidence = %+v", evidence)
	}
	serialized, err := json.Marshal(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("ExampleApp/4.2.1")) || bytes.Contains(serialized, []byte("(iOS)")) {
		t.Fatalf("raw User-Agent was retained: %s", serialized)
	}
}

func TestAnalyzerSkipsContentLengthAndReadsNextMessage(t *testing.T) {
	a := New("upstream_to_client", 2048)
	messages := a.Observe([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 204 No Content\r\n\r\n"))
	if len(messages) != 2 || messages[0].Kind != "response" || messages[0].StatusCode != 200 || messages[1].StatusCode != 204 {
		t.Fatalf("messages = %+v", messages)
	}
	if messages[0].Completeness != "partial" || messages[0].BodyFraming != "content_length" || messages[0].BodyCaptured {
		t.Fatalf("body-bearing response was marked complete: %+v", messages[0])
	}
	if messages[1].Completeness != "complete" || messages[1].BodyFraming != "none" {
		t.Fatalf("bodyless response framing = %+v", messages[1])
	}
}

func TestAnalyzerSkipsFragmentedContentLengthBodyBeforeNextRequest(t *testing.T) {
	a := New("client_to_upstream", 1024)
	wire := []byte("POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\nWikiGET /next HTTP/1.1\r\nHost: example.test\r\n\r\n")
	var messages []Message
	for _, value := range wire {
		messages = append(messages, a.Observe([]byte{value})...)
	}
	if len(messages) != 2 || messages[0].Method != "POST" || messages[1].Method != "GET" || messages[1].Sequence != 2 {
		t.Fatalf("fragmented content-length stream = %+v", messages)
	}
	if messages[0].Completeness != "partial" || messages[0].BodyFraming != "content_length" || messages[0].BodyCaptured {
		t.Fatalf("fragmented request body status = %+v", messages[0])
	}
}

func TestAnalyzerStopsAtCloseDelimitedResponseBody(t *testing.T) {
	a := New("upstream_to_client", 1024)
	messages := a.Observe([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"))
	if len(messages) != 1 || messages[0].StatusCode != 200 {
		t.Fatalf("close-delimited body was parsed as another response: %+v", messages)
	}
	if messages[0].Completeness != "partial" || messages[0].BodyFraming != "close_delimited" || messages[0].BodyCaptured {
		t.Fatalf("close-delimited response was not marked partial: %+v", messages[0])
	}
	if !a.disabled {
		t.Fatal("analyzer remained enabled without a safe response-body delimiter")
	}
}

func TestAnalyzerReadsAfterBodylessResponse(t *testing.T) {
	a := New("upstream_to_client", 1024)
	messages := a.Observe([]byte("HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	if len(messages) != 2 || messages[0].StatusCode != 204 || messages[1].StatusCode != 200 {
		t.Fatalf("messages = %+v", messages)
	}
}

func TestAnalyzerSkipsChunkedBodyAndTrailersAcrossFragments(t *testing.T) {
	a := New("client_to_upstream", 1024)
	wire := []byte("POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=x\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: secret\r\n\r\nGET /next HTTP/1.1\r\nHost: example.test\r\n\r\n")
	var messages []Message
	for _, value := range wire {
		messages = append(messages, a.Observe([]byte{value})...)
	}
	if len(messages) != 2 {
		t.Fatalf("messages = %+v, want two messages after chunked body", messages)
	}
	if messages[0].Method != "POST" || messages[1].Method != "GET" || messages[1].Sequence != 2 {
		t.Fatalf("messages = %+v", messages)
	}
	if messages[0].Completeness != "partial" || messages[0].BodyFraming != "chunked" || messages[0].BodyCaptured || messages[0].TrailerStatus != "not_fingerprinted" {
		t.Fatalf("chunked request omitted-content status = %+v", messages[0])
	}
	serialized, err := json.Marshal(messages)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("Wikipedia")) || bytes.Contains(serialized, []byte("secret")) {
		t.Fatalf("chunked body or trailer leaked into fingerprint: %s", serialized)
	}
}

func TestAnalyzerLabelsUnsupportedTransferEncoding(t *testing.T) {
	a := New("client_to_upstream", 1024)
	messages := a.Observe([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\nopaque body"))
	if len(messages) != 1 || messages[0].Completeness != "partial" || messages[0].BodyFraming != "unsupported_transfer_encoding" {
		t.Fatalf("unsupported transfer coding status = %+v", messages)
	}
	if !a.disabled {
		t.Fatal("analyzer remained active after unsupported transfer framing")
	}
}

func TestAnalyzerRejectsMalformedChunkFraming(t *testing.T) {
	a := New("client_to_upstream", 1024)
	messages := a.Observe([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\nbody\r\n0\r\n\r\nGET /ignored HTTP/1.1\r\n\r\n"))
	if len(messages) != 1 || messages[0].Method != "POST" {
		t.Fatalf("messages = %+v", messages)
	}
	if !a.disabled {
		t.Fatal("analyzer remained active after malformed chunk framing")
	}
}

func TestAnalyzerRejectsMalformedChunkTrailer(t *testing.T) {
	a := New("client_to_upstream", 1024)
	messages := a.Observe([]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-trailer\r\n\r\n"))
	if len(messages) != 1 || messages[0].Completeness != "partial" {
		t.Fatalf("malformed chunk trailer header observation = %+v", messages)
	}
	if !a.disabled {
		t.Fatal("analyzer remained active after malformed trailer syntax")
	}
}

func TestAnalyzerRejectsHTTP2Preface(t *testing.T) {
	a := New("client_to_upstream", 1024)
	if got := a.Observe([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); len(got) != 0 {
		t.Fatalf("HTTP/2 preface was classified as HTTP/1: %+v", got)
	}
}

func FuzzAnalyzer(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		a := New("fuzz", 4096)
		for offset := 0; offset < len(input); {
			end := offset + 1
			if remaining := len(input) - offset; remaining > 17 {
				end = offset + 17
			} else {
				end = len(input)
			}
			a.Observe(input[offset:end])
			offset = end
		}
	})
}
