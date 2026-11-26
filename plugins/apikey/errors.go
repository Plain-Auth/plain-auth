package apikey

// The errors below carry the status, code and message of the API key error
// table. The table's KEY_NOT_RECOVERABLE and INVALID_USER_ID_FROM_API_KEY
// are never answered. INVALID_API_KEY_GETTER_RETURN_TYPE cannot arise,
// because ExtractKey returns a string. A failed key write is a store error,
// answered as 500 INTERNAL_SERVER_ERROR instead of FAILED_TO_UPDATE_API_KEY.
var (
	ErrMissing = problem(404, "KEY_NOT_FOUND", "API Key not found")
	ErrSession = problem(401, "UNAUTHORIZED_SESSION", "Unauthorized or invalid session")
	ErrBanned  = problem(401, "USER_BANNED", "User is banned")

	ErrOrganizationRequired = problem(400, "ORGANIZATION_ID_REQUIRED", "Organization ID is required for organization-owned API keys.")
	ErrMembership           = problem(403, "USER_NOT_MEMBER_OF_ORGANIZATION", "You are not a member of the organization that owns this API key.")
	ErrPermission           = problem(403, "INSUFFICIENT_API_KEY_PERMISSIONS", "You do not have permission to perform this action on organization API keys.")
	ErrOrgPlugin            = problem(500, "ORGANIZATION_PLUGIN_REQUIRED", "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.")

	// ErrNoDefaultConfiguration answers a request that names no configId
	// when no configuration is the default one.
	ErrNoDefaultConfiguration = problem(400, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND", "No default api-key configuration found.")
	// errSignIn answers a signed-out read, list or delete, which need a
	// session before anything else.
	errSignIn = problem(401, "UNAUTHORIZED", "Unauthorized")

	errMetadataType       = problem(400, "INVALID_METADATA_TYPE", "metadata must be an object or undefined")
	errRefillAmount       = problem(400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED", "refillAmount is required when refillInterval is provided")
	errRefillInterval     = problem(400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED", "refillInterval is required when refillAmount is provided")
	errExpiresTooSmall    = problem(400, "EXPIRES_IN_IS_TOO_SMALL", "The expiresIn is smaller than the predefined minimum value.")
	errExpiresTooLarge    = problem(400, "EXPIRES_IN_IS_TOO_LARGE", "The expiresIn is larger than the predefined maximum value.")
	errRemaining          = problem(400, "INVALID_REMAINING", "The remaining count is either too large or too small.")
	errPrefixLength       = problem(400, "INVALID_PREFIX_LENGTH", "The prefix length is either too large or too small.")
	errPrefixFormat       = problem(400, "VALIDATION_ERROR", "[body.prefix] Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.")
	errNameLength         = problem(400, "INVALID_NAME_LENGTH", "The name length is either too large or too small.")
	errMetadataDisabled   = problem(400, "METADATA_DISABLED", "Metadata is disabled.")
	errNoValues           = problem(400, "NO_VALUES_TO_UPDATE", "No values to update.")
	errExpirationDisabled = problem(400, "KEY_DISABLED_EXPIRATION", "Custom key expiration values are disabled.")
	errServerOnly         = problem(400, "SERVER_ONLY_PROPERTY", "The property you're trying to set can only be set from the server auth instance only.")
	errNameRequired       = problem(400, "NAME_REQUIRED", "API Key name is required.")
	invalidSessionKey     = problem(401, "INVALID_API_KEY", "Invalid API key.")
	// A session key shorter than KeyLength or refused by ValidateKey
	// answers 403.
	errRefusedKey = problem(403, "INVALID_API_KEY", "Invalid API key.")
	errReference  = problem(401, "INVALID_REFERENCE_ID_FROM_API_KEY", "The reference id from the API key is invalid.")
)
