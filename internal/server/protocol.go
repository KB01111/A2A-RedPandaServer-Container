package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type protocolVersionInterceptor struct {
	a2asrv.PassthroughCallInterceptor
}

func (protocolVersionInterceptor) Before(
	ctx context.Context,
	callCtx *a2asrv.CallContext,
	_ *a2asrv.Request,
) (context.Context, any, error) {
	versions, ok := callCtx.ServiceParams().Get(a2a.SvcParamVersion)
	if !ok || len(versions) != 1 || strings.TrimSpace(versions[0]) != string(a2a.Version) {
		return ctx, nil, a2a.ErrVersionNotSupported
	}
	return ctx, nil, nil
}

func normalizeServiceParameters(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		request = request.Clone(request.Context())
		normalizeVersionParameter(request)
		normalizeListParameter(request, a2a.SvcParamExtensions)
		next.ServeHTTP(response, request)
	})
}

func normalizeVersionParameter(request *http.Request) {
	headers := splitParameterValues(request.Header.Values(a2a.SvcParamVersion))
	query := splitParameterValues(request.URL.Query()[a2a.SvcParamVersion])
	values := append(headers, query...)
	if len(values) == 2 && values[0] == values[1] {
		values = values[:1]
	}
	request.Header.Del(a2a.SvcParamVersion)
	for _, value := range values {
		request.Header.Add(a2a.SvcParamVersion, value)
	}
}

func normalizeListParameter(request *http.Request, name string) {
	values := append(request.Header.Values(name), request.URL.Query()[name]...)
	request.Header.Del(name)
	for _, value := range splitParameterValues(values) {
		request.Header.Add(name, value)
	}
}

func splitParameterValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for item := range strings.SplitSeq(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				result = append(result, item)
			}
		}
	}
	return result
}

func limitRequestBody(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Body == nil || request.Body == http.NoBody {
			next.ServeHTTP(response, request)
			return
		}
		if request.ContentLength > maxBytes {
			writeRequestTooLarge(response)
			return
		}

		body, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
		closeErr := request.Body.Close()
		if err != nil || closeErr != nil {
			http.Error(response, "failed to read request body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBytes {
			writeRequestTooLarge(response)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		next.ServeHTTP(response, request)
	})
}

func writeRequestTooLarge(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(response).Encode(map[string]any{
		"error": map[string]any{
			"code":    http.StatusRequestEntityTooLarge,
			"status":  "RESOURCE_EXHAUSTED",
			"message": "request body exceeds configured limit",
		},
	})
}
