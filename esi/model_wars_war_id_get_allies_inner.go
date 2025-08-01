/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"encoding/json"
)

// checks if the WarsWarIdGetAlliesInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &WarsWarIdGetAlliesInner{}

// WarsWarIdGetAlliesInner ally object
type WarsWarIdGetAlliesInner struct {
	// Alliance ID if and only if this ally is an alliance
	AllianceId *int64 `json:"alliance_id,omitempty"`
	// Corporation ID if and only if this ally is a corporation
	CorporationId *int64 `json:"corporation_id,omitempty"`
}

// NewWarsWarIdGetAlliesInner instantiates a new WarsWarIdGetAlliesInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWarsWarIdGetAlliesInner() *WarsWarIdGetAlliesInner {
	this := WarsWarIdGetAlliesInner{}
	return &this
}

// NewWarsWarIdGetAlliesInnerWithDefaults instantiates a new WarsWarIdGetAlliesInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWarsWarIdGetAlliesInnerWithDefaults() *WarsWarIdGetAlliesInner {
	this := WarsWarIdGetAlliesInner{}
	return &this
}

// GetAllianceId returns the AllianceId field value if set, zero value otherwise.
func (o *WarsWarIdGetAlliesInner) GetAllianceId() int64 {
	if o == nil || IsNil(o.AllianceId) {
		var ret int64
		return ret
	}
	return *o.AllianceId
}

// GetAllianceIdOk returns a tuple with the AllianceId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WarsWarIdGetAlliesInner) GetAllianceIdOk() (*int64, bool) {
	if o == nil || IsNil(o.AllianceId) {
		return nil, false
	}
	return o.AllianceId, true
}

// HasAllianceId returns a boolean if a field has been set.
func (o *WarsWarIdGetAlliesInner) HasAllianceId() bool {
	if o != nil && !IsNil(o.AllianceId) {
		return true
	}

	return false
}

// SetAllianceId gets a reference to the given int64 and assigns it to the AllianceId field.
func (o *WarsWarIdGetAlliesInner) SetAllianceId(v int64) {
	o.AllianceId = &v
}

// GetCorporationId returns the CorporationId field value if set, zero value otherwise.
func (o *WarsWarIdGetAlliesInner) GetCorporationId() int64 {
	if o == nil || IsNil(o.CorporationId) {
		var ret int64
		return ret
	}
	return *o.CorporationId
}

// GetCorporationIdOk returns a tuple with the CorporationId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WarsWarIdGetAlliesInner) GetCorporationIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CorporationId) {
		return nil, false
	}
	return o.CorporationId, true
}

// HasCorporationId returns a boolean if a field has been set.
func (o *WarsWarIdGetAlliesInner) HasCorporationId() bool {
	if o != nil && !IsNil(o.CorporationId) {
		return true
	}

	return false
}

// SetCorporationId gets a reference to the given int64 and assigns it to the CorporationId field.
func (o *WarsWarIdGetAlliesInner) SetCorporationId(v int64) {
	o.CorporationId = &v
}

func (o WarsWarIdGetAlliesInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o WarsWarIdGetAlliesInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.AllianceId) {
		toSerialize["alliance_id"] = o.AllianceId
	}
	if !IsNil(o.CorporationId) {
		toSerialize["corporation_id"] = o.CorporationId
	}
	return toSerialize, nil
}

type NullableWarsWarIdGetAlliesInner struct {
	value *WarsWarIdGetAlliesInner
	isSet bool
}

func (v NullableWarsWarIdGetAlliesInner) Get() *WarsWarIdGetAlliesInner {
	return v.value
}

func (v *NullableWarsWarIdGetAlliesInner) Set(val *WarsWarIdGetAlliesInner) {
	v.value = val
	v.isSet = true
}

func (v NullableWarsWarIdGetAlliesInner) IsSet() bool {
	return v.isSet
}

func (v *NullableWarsWarIdGetAlliesInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWarsWarIdGetAlliesInner(val *WarsWarIdGetAlliesInner) *NullableWarsWarIdGetAlliesInner {
	return &NullableWarsWarIdGetAlliesInner{value: val, isSet: true}
}

func (v NullableWarsWarIdGetAlliesInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWarsWarIdGetAlliesInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


