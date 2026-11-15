package graphqlapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	ds "github.com/target/goalert/deletionsafety"
)

const deletionCursorDomain = "goalert.deletion-preview.v1\x00"

// Digests bind selection and freshly corroborated actor/scope; they are not
// authority. No actor, Session, Organization ID or manifest is carried here.
type deletionPreviewCursor struct {
	Operation string `json:"operation"`
	Selection string `json:"selection"`
	Scope     string `json:"scope"`
	Policy    string `json:"policy"`
	Impact    string `json:"impact"`
	Position  string `json:"position"`
}

func newDeletionPreviewCursor(targets []ds.Resource, scope, impact string) deletionPreviewCursor {
	// This is only the selector digest. ImpactVersion is always the IMPL1 value.
	data, _ := json.Marshal(targets)
	return deletionPreviewCursor{Operation: "DELETE_RESOURCES", Selection: hexDigest(data), Scope: scope, Policy: ds.PolicyVersion, Impact: impact}
}
func hexDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func encodeDeletionPreviewCursor(signer DeletionCursorSigner, c deletionPreviewCursor) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", previewUnavailable()
	}
	signature, err := signer.Sign(append([]byte(deletionCursorDomain), data...))
	if err != nil {
		return "", previewUnavailable()
	}
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
func decodeDeletionPreviewCursor(signer DeletionCursorSigner, raw string) (*deletionPreviewCursor, error) {
	if len(raw) > 2048 {
		return nil, previewUnavailable()
	}
	payload, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return nil, previewUnavailable()
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, previewUnavailable()
	}
	signature, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, previewUnavailable()
	}
	if valid, _ := signer.Verify(append([]byte(deletionCursorDomain), data...), signature); !valid {
		return nil, previewUnavailable()
	}
	var c deletionPreviewCursor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, previewUnavailable()
	}
	if c.Operation != "DELETE_RESOURCES" || c.Policy == "" || !previewDigestValid(c.Selection) || !previewDigestValid(c.Scope) || !previewDigestValid(c.Impact) || !previewDigestValid(c.Position) {
		return nil, previewUnavailable()
	}
	return &c, nil
}
func previewDigestValid(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
