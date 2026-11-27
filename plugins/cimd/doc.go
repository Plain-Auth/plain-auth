// Package cimd identifies OAuth clients by Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document-02), as another runtime's
// cimd plugin does: a client ID that is an HTTPS URL names a JSON document
// with the client's metadata, which the provider fetches, validates and
// stores through a client discovery.
package cimd
