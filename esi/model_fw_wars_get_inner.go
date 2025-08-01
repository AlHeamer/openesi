/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the FwWarsGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwWarsGetInner{}

// FwWarsGetInner struct for FwWarsGetInner
type FwWarsGetInner struct {
	// The faction ID of the enemy faction.
	AgainstId int64 `json:"against_id"`
	FactionId int64 `json:"faction_id"`
}

type _FwWarsGetInner FwWarsGetInner

// NewFwWarsGetInner instantiates a new FwWarsGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwWarsGetInner(againstId int64, factionId int64) *FwWarsGetInner {
	this := FwWarsGetInner{}
	this.AgainstId = againstId
	this.FactionId = factionId
	return &this
}

// NewFwWarsGetInnerWithDefaults instantiates a new FwWarsGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwWarsGetInnerWithDefaults() *FwWarsGetInner {
	this := FwWarsGetInner{}
	return &this
}

// GetAgainstId returns the AgainstId field value
func (o *FwWarsGetInner) GetAgainstId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.AgainstId
}

// GetAgainstIdOk returns a tuple with the AgainstId field value
// and a boolean to check if the value has been set.
func (o *FwWarsGetInner) GetAgainstIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AgainstId, true
}

// SetAgainstId sets field value
func (o *FwWarsGetInner) SetAgainstId(v int64) {
	o.AgainstId = v
}

// GetFactionId returns the FactionId field value
func (o *FwWarsGetInner) GetFactionId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.FactionId
}

// GetFactionIdOk returns a tuple with the FactionId field value
// and a boolean to check if the value has been set.
func (o *FwWarsGetInner) GetFactionIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FactionId, true
}

// SetFactionId sets field value
func (o *FwWarsGetInner) SetFactionId(v int64) {
	o.FactionId = v
}

func (o FwWarsGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwWarsGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["against_id"] = o.AgainstId
	toSerialize["faction_id"] = o.FactionId
	return toSerialize, nil
}

func (o *FwWarsGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"against_id",
		"faction_id",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varFwWarsGetInner := _FwWarsGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varFwWarsGetInner)

	if err != nil {
		return err
	}

	*o = FwWarsGetInner(varFwWarsGetInner)

	return err
}

type NullableFwWarsGetInner struct {
	value *FwWarsGetInner
	isSet bool
}

func (v NullableFwWarsGetInner) Get() *FwWarsGetInner {
	return v.value
}

func (v *NullableFwWarsGetInner) Set(val *FwWarsGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableFwWarsGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableFwWarsGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwWarsGetInner(val *FwWarsGetInner) *NullableFwWarsGetInner {
	return &NullableFwWarsGetInner{value: val, isSet: true}
}

func (v NullableFwWarsGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwWarsGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


