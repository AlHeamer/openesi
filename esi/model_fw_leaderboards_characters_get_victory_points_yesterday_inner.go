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

// checks if the FwLeaderboardsCharactersGetVictoryPointsYesterdayInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwLeaderboardsCharactersGetVictoryPointsYesterdayInner{}

// FwLeaderboardsCharactersGetVictoryPointsYesterdayInner yesterday object
type FwLeaderboardsCharactersGetVictoryPointsYesterdayInner struct {
	// Amount of victory points
	Amount *int64 `json:"amount,omitempty"`
	CharacterId *int64 `json:"character_id,omitempty"`
}

// NewFwLeaderboardsCharactersGetVictoryPointsYesterdayInner instantiates a new FwLeaderboardsCharactersGetVictoryPointsYesterdayInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwLeaderboardsCharactersGetVictoryPointsYesterdayInner() *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner {
	this := FwLeaderboardsCharactersGetVictoryPointsYesterdayInner{}
	return &this
}

// NewFwLeaderboardsCharactersGetVictoryPointsYesterdayInnerWithDefaults instantiates a new FwLeaderboardsCharactersGetVictoryPointsYesterdayInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwLeaderboardsCharactersGetVictoryPointsYesterdayInnerWithDefaults() *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner {
	this := FwLeaderboardsCharactersGetVictoryPointsYesterdayInner{}
	return &this
}

// GetAmount returns the Amount field value if set, zero value otherwise.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) GetAmount() int64 {
	if o == nil || IsNil(o.Amount) {
		var ret int64
		return ret
	}
	return *o.Amount
}

// GetAmountOk returns a tuple with the Amount field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) GetAmountOk() (*int64, bool) {
	if o == nil || IsNil(o.Amount) {
		return nil, false
	}
	return o.Amount, true
}

// HasAmount returns a boolean if a field has been set.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) HasAmount() bool {
	if o != nil && !IsNil(o.Amount) {
		return true
	}

	return false
}

// SetAmount gets a reference to the given int64 and assigns it to the Amount field.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) SetAmount(v int64) {
	o.Amount = &v
}

// GetCharacterId returns the CharacterId field value if set, zero value otherwise.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) GetCharacterId() int64 {
	if o == nil || IsNil(o.CharacterId) {
		var ret int64
		return ret
	}
	return *o.CharacterId
}

// GetCharacterIdOk returns a tuple with the CharacterId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) GetCharacterIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CharacterId) {
		return nil, false
	}
	return o.CharacterId, true
}

// HasCharacterId returns a boolean if a field has been set.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) HasCharacterId() bool {
	if o != nil && !IsNil(o.CharacterId) {
		return true
	}

	return false
}

// SetCharacterId gets a reference to the given int64 and assigns it to the CharacterId field.
func (o *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) SetCharacterId(v int64) {
	o.CharacterId = &v
}

func (o FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Amount) {
		toSerialize["amount"] = o.Amount
	}
	if !IsNil(o.CharacterId) {
		toSerialize["character_id"] = o.CharacterId
	}
	return toSerialize, nil
}

type NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner struct {
	value *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner
	isSet bool
}

func (v NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) Get() *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner {
	return v.value
}

func (v *NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) Set(val *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) {
	v.value = val
	v.isSet = true
}

func (v NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) IsSet() bool {
	return v.isSet
}

func (v *NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner(val *FwLeaderboardsCharactersGetVictoryPointsYesterdayInner) *NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner {
	return &NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner{value: val, isSet: true}
}

func (v NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwLeaderboardsCharactersGetVictoryPointsYesterdayInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


