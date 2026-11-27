package polar

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
	"github.com/polarsource/polar-go/retry"
)

// Page is one page of a customer list, in Polar's snake-case field names.
// Each item is a documented subset of Polar's object, where another runtime
// returns Polar's object whole, so secrets and personal details such as
// license keys or billing addresses stay at Polar.
type Page[T any] struct {
	Items      []T        `json:"items"`
	Pagination Pagination `json:"pagination"`
}

// Pagination reports Polar's item count and last page for the list.
type Pagination struct {
	TotalCount int64 `json:"total_count"`
	MaxPage    int64 `json:"max_page"`
}

// CustomerBenefit is a benefit currently granted to the signed-in customer.
// Revoked or pending grants are left out of the page, though Polar counts
// them in its pagination.
type CustomerBenefit struct {
	ID             string    `json:"id"`
	BenefitID      string    `json:"benefit_id"`
	BenefitType    string    `json:"benefit_type"`
	Description    string    `json:"description"`
	GrantedAt      time.Time `json:"granted_at"`
	SubscriptionID *string   `json:"subscription_id"`
	OrderID        *string   `json:"order_id"`
}

// CustomerOrder is an order of the signed-in customer, such as a purchase
// or a renewal.
type CustomerOrder struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	Status         string    `json:"status"`
	Paid           bool      `json:"paid"`
	BillingReason  string    `json:"billing_reason"`
	ProductID      *string   `json:"product_id"`
	SubscriptionID *string   `json:"subscription_id"`
	Currency       string    `json:"currency"`
	SubtotalAmount int64     `json:"subtotal_amount"`
	DiscountAmount int64     `json:"discount_amount"`
	NetAmount      int64     `json:"net_amount"`
	TaxAmount      int64     `json:"tax_amount"`
	TotalAmount    int64     `json:"total_amount"`
	RefundedAmount int64     `json:"refunded_amount"`
	Description    string    `json:"description"`
}

// CustomerSubscription is one of the signed-in customer's own subscriptions.
type CustomerSubscription struct {
	ID                 string     `json:"id"`
	ProductID          string     `json:"product_id"`
	Status             string     `json:"status"`
	Amount             int64      `json:"amount"`
	Currency           string     `json:"currency"`
	RecurringInterval  string     `json:"recurring_interval"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CancelAtPeriodEnd  bool       `json:"cancel_at_period_end"`
	CanceledAt         *time.Time `json:"canceled_at"`
	StartedAt          *time.Time `json:"started_at"`
	EndsAt             *time.Time `json:"ends_at"`
	EndedAt            *time.Time `json:"ended_at"`
}

// maxListLimit bounds a list page, as Polar does.
const maxListLimit = 100

// listQuery is a checked list request: paging, the route's one filter and,
// where the route accepts one, an organization reference.
type listQuery struct {
	page, limit *int64
	filter      string
	reference   string
}

func invalidQuery() error {
	return failure(400, "POLAR_INVALID_QUERY", "Use page, limit and the documented filter")
}

// listRequest reads page, limit, the route's optional filter and, when
// reference is set, referenceId, each at most once, and refuses any other
// query key.
func listRequest(c auth.EndpointContext, filter string, reference bool) (listQuery, error) {
	var q listQuery
	for key, values := range c.Request.URL.Query() {
		if len(values) != 1 {
			return q, invalidQuery()
		}
		switch key {
		case "page", "limit":
			n, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || n < 1 || key == "limit" && n > maxListLimit {
				return q, invalidQuery()
			}
			if key == "page" {
				q.page = &n
			} else {
				q.limit = &n
			}
		case filter:
			if filter == "" {
				return q, invalidQuery()
			}
			q.filter = values[0]
		case "referenceId":
			if !reference {
				return q, invalidQuery()
			}
			if !validReference(values[0]) {
				return q, failure(400, "POLAR_INVALID_REFERENCE", "referenceId must be an organization ID")
			}
			q.reference = values[0]
		default:
			return q, invalidQuery()
		}
	}
	return q, nil
}

// listSession checks the owner and opens a server-side customer session
// for the signed-in account, whose token reads Polar's customer portal.
func (s *Service) listSession(c auth.EndpointContext) (*auth.SessionResult, *components.CustomerSession, error) {
	session, err := s.owner(c)
	if err != nil {
		return nil, nil, err
	}
	p, err := s.customerSession(c, session, nil)
	if err != nil {
		return nil, nil, err
	}
	return session, p, nil
}

// subset converts Polar's items through their JSON into the documented
// item, keeping those keep accepts. An item for another customer refuses
// the whole page.
func subset[T any](items any, customer string, keep func(raw map[string]any) bool) ([]T, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, customerMismatch()
	}
	var whole []map[string]any
	var typed []T
	if json.Unmarshal(raw, &whole) != nil || json.Unmarshal(raw, &typed) != nil || len(whole) != len(typed) {
		return nil, customerMismatch()
	}
	out := make([]T, 0, len(typed))
	for i, item := range whole {
		if id, _ := item["customer_id"].(string); id != customer {
			return nil, customerMismatch()
		}
		if keep == nil || keep(item) {
			out = append(out, typed[i])
		}
	}
	return out, nil
}

func (s *Service) customerBenefits(c auth.EndpointContext) (any, error) {
	q, err := listRequest(c, "", false)
	if err != nil {
		return nil, err
	}
	session, p, err := s.listSession(c)
	if err != nil {
		return nil, err
	}
	reply, err := s.opts.Client.CustomerPortal.BenefitGrants.List(c.Request.Context(), operations.CustomerPortalBenefitGrantsListRequest{Page: q.page, Limit: q.limit},
		operations.CustomerPortalBenefitGrantsListSecurity{CustomerSession: &p.Token}, versioned())
	if err != nil || reply == nil || reply.ListResourceCustomerBenefitGrant == nil {
		return nil, customerProviderError(err)
	}
	list := reply.ListResourceCustomerBenefitGrant
	type grant struct {
		CustomerBenefit
		Benefit struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"benefit"`
	}
	items, err := subset[grant](list.Items, p.CustomerID, func(raw map[string]any) bool {
		granted, _ := raw["is_granted"].(bool)
		revoked, _ := raw["is_revoked"].(bool)
		return granted && !revoked
	})
	if err != nil {
		return nil, err
	}
	out := Page[CustomerBenefit]{Items: make([]CustomerBenefit, len(items)), Pagination: Pagination(list.Pagination)}
	for i, g := range items {
		out.Items[i] = g.CustomerBenefit
		out.Items[i].BenefitType, out.Items[i].Description = g.Benefit.Type, g.Benefit.Description
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) customerOrders(c auth.EndpointContext) (any, error) {
	q, err := listRequest(c, "productBillingType", false)
	if err != nil {
		return nil, err
	}
	req := operations.CustomerPortalOrdersListRequest{Page: q.page, Limit: q.limit}
	switch q.filter {
	case "":
	case string(components.ProductBillingTypeOneTime), string(components.ProductBillingTypeRecurring):
		billing := operations.CreateCustomerPortalOrdersListQueryParamProductBillingTypeFilterProductBillingType(components.ProductBillingType(q.filter))
		req.ProductBillingType = &billing
	default:
		return nil, invalidQuery()
	}
	session, p, err := s.listSession(c)
	if err != nil {
		return nil, err
	}
	reply, err := s.opts.Client.CustomerPortal.Orders.List(c.Request.Context(), req, operations.CustomerPortalOrdersListSecurity{CustomerSession: &p.Token}, versioned())
	if err != nil || reply == nil || reply.ListResourceCustomerOrder == nil {
		return nil, customerProviderError(err)
	}
	items, err := subset[CustomerOrder](reply.ListResourceCustomerOrder.Items, p.CustomerID, nil)
	if err != nil {
		return nil, err
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return Page[CustomerOrder]{Items: items, Pagination: Pagination(reply.ListResourceCustomerOrder.Pagination)}, nil
}

func (s *Service) customerSubscriptions(c auth.EndpointContext) (any, error) {
	q, err := listRequest(c, "active", s.opts.Organization != nil)
	if err != nil {
		return nil, err
	}
	req := operations.CustomerPortalSubscriptionsListRequest{Page: q.page, Limit: q.limit}
	switch q.filter {
	case "":
	case "true", "false":
		active := q.filter == "true"
		req.Active = &active
	default:
		return nil, invalidQuery()
	}
	if q.reference != "" {
		return s.referenceSubscriptions(c, q, req.Active)
	}
	session, p, err := s.listSession(c)
	if err != nil {
		return nil, err
	}
	reply, err := s.opts.Client.CustomerPortal.Subscriptions.List(c.Request.Context(), req, operations.CustomerPortalSubscriptionsListSecurity{CustomerSession: &p.Token}, versioned())
	if err != nil || reply == nil || reply.ListResourceCustomerSubscription == nil {
		return nil, customerProviderError(err)
	}
	items, err := subset[CustomerSubscription](reply.ListResourceCustomerSubscription.Items, p.CustomerID, nil)
	if err != nil {
		return nil, err
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return Page[CustomerSubscription]{Items: items, Pagination: Pagination(reply.ListResourceCustomerSubscription.Pagination)}, nil
}

// ReferenceSubscription is a subscription a member bought for an
// organization, listed by referenceId.
type ReferenceSubscription struct {
	CustomerSubscription
	ReferenceID string `json:"reference_id"`
}

// referenceSubscriptions lists the merchant's subscriptions whose
// referenceId metadata names the organization, for a member the host
// approves. Another runtime lists them for any signed-in caller and
// returns Polar's objects whole; here each item is the personal list's
// subset, so customer details and other metadata stay at Polar.
func (s *Service) referenceSubscriptions(c auth.EndpointContext, q listQuery, active *bool) (any, error) {
	session, err := s.owner(c)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeReference(c, session, q.reference, "list-subscription"); err != nil {
		return nil, err
	}
	// The SDK prints a metadata filter as a Go struct, so the query is built
	// here and carried on the server URL, which the SDK then sends as is.
	query := url.Values{"organization_id": {s.opts.OrganizationID}, "metadata[" + referenceMetadata + "]": {q.reference}}
	if active != nil {
		query.Set("active", strconv.FormatBool(*active))
	}
	if q.page != nil {
		query.Set("page", strconv.FormatInt(*q.page, 10))
	}
	if q.limit != nil {
		query.Set("limit", strconv.FormatInt(*q.limit, 10))
	}
	server := strings.TrimSuffix(s.opts.Organization.serverURL(), "/") + "/?" + query.Encode()
	reply, err := s.opts.Client.Subscriptions.List(c.Request.Context(), operations.SubscriptionsListRequest{},
		operations.WithServerURL(server), versioned(), operations.WithRetries(retry.Config{Strategy: "none"}))
	if err != nil || reply == nil || reply.ListResourceSubscription == nil {
		return nil, failure(502, "POLAR_SUBSCRIPTIONS_UNAVAILABLE", "Unable to list the organization's subscriptions at Polar")
	}
	list := reply.ListResourceSubscription
	out := Page[ReferenceSubscription]{Items: make([]ReferenceSubscription, 0, len(list.Items)), Pagination: Pagination(list.Pagination)}
	for _, it := range list.Items {
		if ref := it.Metadata[referenceMetadata].Str; ref == nil || *ref != q.reference || it.Customer.OrganizationID != s.opts.OrganizationID {
			return nil, customerMismatch()
		}
		out.Items = append(out.Items, ReferenceSubscription{ReferenceID: q.reference, CustomerSubscription: CustomerSubscription{
			ID: it.ID, ProductID: it.ProductID, Status: string(it.Status), Amount: it.Amount, Currency: it.Currency,
			RecurringInterval: string(it.RecurringInterval), CurrentPeriodStart: it.CurrentPeriodStart, CurrentPeriodEnd: it.CurrentPeriodEnd,
			CancelAtPeriodEnd: it.CancelAtPeriodEnd, CanceledAt: it.CanceledAt, StartedAt: it.StartedAt, EndsAt: it.EndsAt, EndedAt: it.EndedAt,
		}})
	}
	// The member may have left while Polar answered.
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	if err := s.authorizeReference(c, session, q.reference, "list-subscription"); err != nil {
		return nil, err
	}
	return out, nil
}
