package polar

import (
	"strconv"
	"time"

	"github.com/polarsource/polar-go/models/components"
)

// CustomerState is the public, merchant-wide personal billing summary. It excludes merchant metadata.
type CustomerState struct {
	ID                  string               `json:"id"`
	Type                string               `json:"type"`
	ExternalID          string               `json:"external_id"`
	OrganizationID      string               `json:"organization_id"`
	Email               string               `json:"email"`
	Name                *string              `json:"name"`
	ActiveSubscriptions []ActiveSubscription `json:"active_subscriptions"`
	GrantedBenefits     []BenefitGrant       `json:"granted_benefits"`
	ActiveMeters        []ActiveMeter        `json:"active_meters"`
}

// ActiveSubscription identifies the product and current service period.
type ActiveSubscription struct {
	ID                string    `json:"id"`
	ProductID         string    `json:"product_id"`
	Status            string    `json:"status"`
	CurrentPeriodEnd  time.Time `json:"current_period_end"`
	CancelAtPeriodEnd bool      `json:"cancel_at_period_end"`
	// ReferenceID is the organization the subscription bills, from its
	// referenceId metadata, or "" for the customer.
	ReferenceID string `json:"reference_id"`
}

// BenefitGrant describes a benefit currently granted to the individual customer.
type BenefitGrant struct {
	ID          string    `json:"id"`
	BenefitID   string    `json:"benefit_id"`
	BenefitType string    `json:"benefit_type"`
	GrantedAt   time.Time `json:"granted_at"`
}

// ActiveMeter records the customer's totals for an active meter in the merchant account.
type ActiveMeter struct {
	ID            string  `json:"id"`
	MeterID       string  `json:"meter_id"`
	ConsumedUnits float64 `json:"consumed_units"`
	CreditedUnits int64   `json:"credited_units"`
	Balance       float64 `json:"balance"`
}

func publicState(customer *components.CustomerStateIndividual) CustomerState {
	result := CustomerState{
		ID: customer.ID, Type: "individual", ExternalID: val(customer.ExternalID),
		OrganizationID: customer.OrganizationID, Email: customer.Email, Name: customer.Name,
		ActiveSubscriptions: make([]ActiveSubscription, 0, len(customer.ActiveSubscriptions)),
		GrantedBenefits:     make([]BenefitGrant, 0, len(customer.GrantedBenefits)),
		ActiveMeters:        make([]ActiveMeter, 0, len(customer.ActiveMeters)),
	}
	for _, sub := range customer.ActiveSubscriptions {
		result.ActiveSubscriptions = append(result.ActiveSubscriptions, ActiveSubscription{
			ID: sub.ID, ProductID: sub.ProductID, Status: string(sub.Status),
			CurrentPeriodEnd: sub.CurrentPeriodEnd, CancelAtPeriodEnd: sub.CancelAtPeriodEnd, ReferenceID: metadataText(sub.Metadata[referenceMetadata]),
		})
	}
	for _, grant := range customer.GrantedBenefits {
		result.GrantedBenefits = append(result.GrantedBenefits, BenefitGrant{
			ID: grant.ID, BenefitID: grant.BenefitID, BenefitType: string(grant.BenefitType), GrantedAt: grant.GrantedAt,
		})
	}
	for _, meter := range customer.ActiveMeters {
		result.ActiveMeters = append(result.ActiveMeters, ActiveMeter{
			ID: meter.ID, MeterID: meter.MeterID, ConsumedUnits: meter.ConsumedUnits,
			CreditedUnits: meter.CreditedUnits, Balance: meter.Balance,
		})
	}
	return result
}

// metadataText is a metadata value as text: a string as itself, another
// type in its text form, and an absent key as "". A purchase for an
// organization therefore never reads as personal.
func metadataText(m components.MetadataOutputType) string {
	switch {
	case m.Str != nil:
		return *m.Str
	case m.Integer != nil:
		return strconv.FormatInt(*m.Integer, 10)
	case m.Number != nil:
		return strconv.FormatFloat(*m.Number, 'g', -1, 64)
	case m.Boolean != nil:
		return strconv.FormatBool(*m.Boolean)
	}
	return ""
}
