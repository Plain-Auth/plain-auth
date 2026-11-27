package polar

import (
	auth "github.com/Plain-Org/plain-auth"
	"github.com/polarsource/polar-go/models/operations"
)

// UsageOptions enables the signed-in customer's meter list. Browser usage
// ingestion is not offered yet.
type UsageOptions struct{}

// CustomerMeter is the signed-in customer's consumption on one meter.
type CustomerMeter struct {
	ID            string    `json:"id"`
	CustomerID    string    `json:"customer_id"`
	MeterID       string    `json:"meter_id"`
	Meter         MeterInfo `json:"meter"`
	ConsumedUnits float64   `json:"consumed_units"`
	CreditedUnits float64   `json:"credited_units"`
	Balance       float64   `json:"balance"`
}

// MeterInfo names a meter.
type MeterInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// customerMeters lists the signed-in customer's meters through Polar's
// customer portal with a server-held customer session, whose token reads
// only that customer's data, as another runtime's usage.meters.list does.
func (s *Service) customerMeters(c auth.EndpointContext) (any, error) {
	q, err := listRequest(c, "")
	if err != nil {
		return nil, err
	}
	session, p, err := s.listSession(c)
	if err != nil {
		return nil, err
	}
	reply, err := s.opts.Client.CustomerPortal.CustomerMeters.List(c.Request.Context(), operations.CustomerPortalCustomerMetersListRequest{Page: q.page, Limit: q.limit},
		operations.CustomerPortalCustomerMetersListSecurity{CustomerSession: &p.Token}, versioned())
	if err != nil || reply == nil || reply.ListResourceCustomerCustomerMeter == nil {
		return nil, customerProviderError(err)
	}
	items, err := subset[CustomerMeter](reply.ListResourceCustomerCustomerMeter.Items, p.CustomerID, nil)
	if err != nil {
		return nil, err
	}
	if err = s.recheckCustomer(c, session); err != nil {
		return nil, err
	}
	return Page[CustomerMeter]{Items: items, Pagination: Pagination(reply.ListResourceCustomerCustomerMeter.Pagination)}, nil
}
