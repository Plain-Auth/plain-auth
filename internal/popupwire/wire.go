// Package popupwire defines the popup protocol shared by the handler and browser clients.
package popupwire

const MessageType = "stonewrit:oauth-popup"
const DataElementID = "oauth-popup-data"
const MarkerCookie = "oauth_popup"
const CompletionScript = `(() => {
  const element = document.getElementById("oauth-popup-data");
  const {targetOrigin, ...message} = JSON.parse(element.textContent);
  if (window.opener) {
    window.opener.postMessage(message, targetOrigin);
  }
  window.close();
})();`
const ScriptCSPHash = "sha256-VfGwWqnxz3xbDcjPlH8nS6en/U40T7oWVs2vFGtM8yY="

type Error struct {
	Code        string `json:"code"`
	Description string `json:"description,omitempty"`
}

// Message is sent to the trusted opener. A successful handoff carries a signed session token.
type Message struct {
	Type       string `json:"type"`
	Nonce      string `json:"nonce"`
	Token      string `json:"token,omitempty"`
	RedirectTo string `json:"redirectTo,omitempty"`
	Error      *Error `json:"error,omitempty"`
}

// Data is the inert payload embedded in the completion page.
type Data struct {
	Message
	TargetOrigin string `json:"targetOrigin"`
}
