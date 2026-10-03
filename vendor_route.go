package pkcs11

import (
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// cloneRoute isolates a route before a VendorModule is allowed to adapt it.
func cloneRoute(route Route) Route {
	route.Intent.OAEPLabel = slices.Clone(route.Intent.OAEPLabel)
	route.Intent.IV = slices.Clone(route.Intent.IV)
	route.Intent.AAD = slices.Clone(route.Intent.AAD)
	route.Intent.Context = slices.Clone(route.Intent.Context)
	route.Mechanism = cloneMechanism(route.Mechanism)
	route.PublicTemplate = cloneAttributeTemplate(route.PublicTemplate)
	route.PrivateTemplate = cloneAttributeTemplate(route.PrivateTemplate)
	route.SecretTemplate = cloneAttributeTemplate(route.SecretTemplate)
	route.Reasons = slices.Clone(route.Reasons)
	return route
}

// adaptVendorRoute delegates every provider-specific route transformation to the
// selected VendorModule. With no module selected, the standard route is returned
// unchanged.
func adaptVendorRoute(device Device, route Route) (Route, error) {
	if device.vendor == nil {
		return route, nil
	}
	adapted, err := device.vendor.AdaptRoute(cloneDevice(device), cloneRoute(route))
	if err != nil {
		return Route{}, err
	}
	if adapted.Mechanism == nil && route.Mechanism != nil {
		adapted.Mechanism = cloneMechanism(route.Mechanism)
	}
	return adapted, nil
}

// NewVendorMechanism is a convenience for vendor modules constructing a route.
func NewVendorMechanism(mechanism uint, parameter any) *raw.Mechanism {
	return raw.NewMechanism(mechanism, parameter)
}
