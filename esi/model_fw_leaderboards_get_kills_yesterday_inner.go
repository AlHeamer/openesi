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

// checks if the FwLeaderboardsGetKillsYesterdayInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwLeaderboardsGetKillsYesterdayInner{}

// FwLeaderboardsGetKillsYesterdayInner yesterday object
type FwLeaderboardsGetKillsYesterdayInner struct {
	// Amount of kills
	Amount *int64 `json:"amount,omitempty"`
	FactionId *int64 `json:"faction_id,omitempty"`
}

// NewFwLeaderboardsGetKillsYesterdayInner instantiates a new FwLeaderboardsGetKillsYesterdayInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwLeaderboardsGetKillsYesterdayInner() *FwLeaderboardsGetKillsYesterdayInner {
	this := FwLeaderboardsGetKillsYesterdayInner{}
	return &this
}

// NewFwLeaderboardsGetKillsYesterdayInnerWithDefaults instantiates a new FwLeaderboardsGetKillsYesterdayInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwLeaderboardsGetKillsYesterdayInnerWithDefaults() *FwLeaderboardsGetKillsYesterdayInner {
	this := FwLeaderboardsGetKillsYesterdayInner{}
	return &this
}

// GetAmount returns the Amount field value if set, zero value otherwise.
func (o *FwLeaderboardsGetKillsYesterdayInner) GetAmount() int64 {
	if o == nil || IsNil(o.Amount) {
		var ret int64
		return ret
	}
	return *o.Amount
}

// GetAmountOk returns a tuple with the Amount field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsGetKillsYesterdayInner) GetAmountOk() (*int64, bool) {
	if o == nil || IsNil(o.Amount) {
		return nil, false
	}
	return o.Amount, true
}

// HasAmount returns a boolean if a field has been set.
func (o *FwLeaderboardsGetKillsYesterdayInner) HasAmount() bool {
	if o != nil && !IsNil(o.Amount) {
		return true
	}

	return false
}

// SetAmount gets a reference to the given int64 and assigns it to the Amount field.
func (o *FwLeaderboardsGetKillsYesterdayInner) SetAmount(v int64) {
	o.Amount = &v
}

// GetFactionId returns the FactionId field value if set, zero value otherwise.
func (o *FwLeaderboardsGetKillsYesterdayInner) GetFactionId() int64 {
	if o == nil || IsNil(o.FactionId) {
		var ret int64
		return ret
	}
	return *o.FactionId
}

// GetFactionIdOk returns a tuple with the FactionId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsGetKillsYesterdayInner) GetFactionIdOk() (*int64, bool) {
	if o == nil || IsNil(o.FactionId) {
		return nil, false
	}
	return o.FactionId, true
}

// HasFactionId returns a boolean if a field has been set.
func (o *FwLeaderboardsGetKillsYesterdayInner) HasFactionId() bool {
	if o != nil && !IsNil(o.FactionId) {
		return true
	}

	return false
}

// SetFactionId gets a reference to the given int64 and assigns it to the FactionId field.
func (o *FwLeaderboardsGetKillsYesterdayInner) SetFactionId(v int64) {
	o.FactionId = &v
}

func (o FwLeaderboardsGetKillsYesterdayInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwLeaderboardsGetKillsYesterdayInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Amount) {
		toSerialize["amount"] = o.Amount
	}
	if !IsNil(o.FactionId) {
		toSerialize["faction_id"] = o.FactionId
	}
	return toSerialize, nil
}

type NullableFwLeaderboardsGetKillsYesterdayInner struct {
	value *FwLeaderboardsGetKillsYesterdayInner
	isSet bool
}

func (v NullableFwLeaderboardsGetKillsYesterdayInner) Get() *FwLeaderboardsGetKillsYesterdayInner {
	return v.value
}

func (v *NullableFwLeaderboardsGetKillsYesterdayInner) Set(val *FwLeaderboardsGetKillsYesterdayInner) {
	v.value = val
	v.isSet = true
}

func (v NullableFwLeaderboardsGetKillsYesterdayInner) IsSet() bool {
	return v.isSet
}

func (v *NullableFwLeaderboardsGetKillsYesterdayInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwLeaderboardsGetKillsYesterdayInner(val *FwLeaderboardsGetKillsYesterdayInner) *NullableFwLeaderboardsGetKillsYesterdayInner {
	return &NullableFwLeaderboardsGetKillsYesterdayInner{value: val, isSet: true}
}

func (v NullableFwLeaderboardsGetKillsYesterdayInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwLeaderboardsGetKillsYesterdayInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


