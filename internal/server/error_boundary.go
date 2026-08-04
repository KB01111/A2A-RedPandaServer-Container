package server

import (
	"context"
	"errors"
	"log/slog"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

type errorBoundaryInterceptor struct {
	a2asrv.PassthroughCallInterceptor
	logger *slog.Logger
}

func (i errorBoundaryInterceptor) After(_ context.Context, callCtx *a2asrv.CallContext, response *a2asrv.Response) error {
	if response == nil || response.Err == nil {
		return nil
	}
	original := response.Err
	response.Err = clientSafeError(original)
	if response.Err == a2a.ErrInternalError && original != a2a.ErrInternalError {
		i.logger.Error("A2A call failed", "method", callCtx.Method(), "error", original)
	}
	return nil
}

func clientSafeError(err error) error {
	var protocolError *a2a.Error
	if errors.As(err, &protocolError) {
		if errors.Is(protocolError, a2a.ErrInternalError) || errors.Is(protocolError, a2a.ErrServerError) {
			return a2a.ErrInternalError
		}
		for _, safe := range clientSafeSentinels {
			if errors.Is(protocolError, safe) {
				return protocolError
			}
		}
		return a2a.ErrInternalError
	}
	for _, safe := range clientSafeSentinels {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return a2a.ErrInternalError
}

var clientSafeSentinels = []error{
	context.Canceled,
	context.DeadlineExceeded,
	a2a.ErrParseError,
	a2a.ErrInvalidRequest,
	a2a.ErrMethodNotFound,
	a2a.ErrInvalidParams,
	a2a.ErrTaskNotFound,
	a2a.ErrTaskNotCancelable,
	a2a.ErrPushNotificationNotSupported,
	a2a.ErrUnsupportedOperation,
	a2a.ErrUnsupportedContentType,
	a2a.ErrInvalidAgentResponse,
	a2a.ErrExtendedCardNotConfigured,
	a2a.ErrExtensionSupportRequired,
	a2a.ErrVersionNotSupported,
	a2a.ErrUnauthenticated,
	a2a.ErrUnauthorized,
}
