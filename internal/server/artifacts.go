package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/KB01111/A2A-RedPandaServer-Container/internal/artifact"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
)

func newArtifactDownloadHandler(resolver artifact.DownloadResolver, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity, ok := auth.IdentityFromContext(request.Context())
		if !ok {
			http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		download, err := resolver.ResolveDownload(request.Context(), artifact.Owner{
			Issuer: identity.Issuer, Tenant: identity.Tenant, Subject: identity.Subject,
		}, request.PathValue("objectID"))
		if errors.Is(err, artifact.ErrObjectNotFound) {
			http.Error(writer, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Error("resolve artifact download", "error", err)
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Cache-Control", "private, no-store")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		http.Redirect(writer, request, download.Presigned.URL, http.StatusTemporaryRedirect)
	})
}
