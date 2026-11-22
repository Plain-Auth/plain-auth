package plainauth

// Redirect returns a 302 endpoint result for a callback allowed by this Auth instance.
func (c EndpointContext) Redirect(callback string) (any, error) {
	target, err := c.Auth.CallbackURL(callback)
	if err != nil {
		return nil, err
	}
	return authRedirect(target), nil
}
