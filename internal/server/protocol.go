package server

import (
	"context"
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
		values := request.Header.Values(a2a.SvcParamExtensions)
		if len(values) == 0 {
			next.ServeHTTP(response, request)
			return
		}

		request = request.Clone(request.Context())
		request.Header.Del(a2a.SvcParamExtensions)
		for _, value := range values {
			for extension := range strings.SplitSeq(value, ",") {
				if extension = strings.TrimSpace(extension); extension != "" {
					request.Header.Add(a2a.SvcParamExtensions, extension)
				}
			}
		}
		next.ServeHTTP(response, request)
	})
}
