package sso

// UserResolutionStore marks a store whose enterprise sign-in honours
// OAuthLoginOptions.SelectUserID and UpdateSelectedProfile.
type UserResolutionStore interface {
	ResolvesSSOUsers()
}
