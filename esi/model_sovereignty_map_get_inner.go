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

// checks if the SovereigntyMapGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SovereigntyMapGetInner{}

// SovereigntyMapGetInner struct for SovereigntyMapGetInner
type SovereigntyMapGetInner struct {
	AllianceId *int64 `json:"alliance_id,omitempty"`
	CorporationId *int64 `json:"corporation_id,omitempty"`
	FactionId *int64 `json:"faction_id,omitempty"`
	SystemId int64 `json:"system_id"`
}

type _SovereigntyMapGetInner SovereigntyMapGetInner

// NewSovereigntyMapGetInner instantiates a new SovereigntyMapGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSovereigntyMapGetInner(systemId int64) *SovereigntyMapGetInner {
	this := SovereigntyMapGetInner{}
	this.SystemId = systemId
	return &this
}

// NewSovereigntyMapGetInnerWithDefaults instantiates a new SovereigntyMapGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSovereigntyMapGetInnerWithDefaults() *SovereigntyMapGetInner {
	this := SovereigntyMapGetInner{}
	return &this
}

// GetAllianceId returns the AllianceId field value if set, zero value otherwise.
func (o *SovereigntyMapGetInner) GetAllianceId() int64 {
	if o == nil || IsNil(o.AllianceId) {
		var ret int64
		return ret
	}
	return *o.AllianceId
}

// GetAllianceIdOk returns a tuple with the AllianceId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SovereigntyMapGetInner) GetAllianceIdOk() (*int64, bool) {
	if o == nil || IsNil(o.AllianceId) {
		return nil, false
	}
	return o.AllianceId, true
}

// HasAllianceId returns a boolean if a field has been set.
func (o *SovereigntyMapGetInner) HasAllianceId() bool {
	if o != nil && !IsNil(o.AllianceId) {
		return true
	}

	return false
}

// SetAllianceId gets a reference to the given int64 and assigns it to the AllianceId field.
func (o *SovereigntyMapGetInner) SetAllianceId(v int64) {
	o.AllianceId = &v
}

// GetCorporationId returns the CorporationId field value if set, zero value otherwise.
func (o *SovereigntyMapGetInner) GetCorporationId() int64 {
	if o == nil || IsNil(o.CorporationId) {
		var ret int64
		return ret
	}
	return *o.CorporationId
}

// GetCorporationIdOk returns a tuple with the CorporationId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SovereigntyMapGetInner) GetCorporationIdOk() (*int64, bool) {
	if o == nil || IsNil(o.CorporationId) {
		return nil, false
	}
	return o.CorporationId, true
}

// HasCorporationId returns a boolean if a field has been set.
func (o *SovereigntyMapGetInner) HasCorporationId() bool {
	if o != nil && !IsNil(o.CorporationId) {
		return true
	}

	return false
}

// SetCorporationId gets a reference to the given int64 and assigns it to the CorporationId field.
func (o *SovereigntyMapGetInner) SetCorporationId(v int64) {
	o.CorporationId = &v
}

// GetFactionId returns the FactionId field value if set, zero value otherwise.
func (o *SovereigntyMapGetInner) GetFactionId() int64 {
	if o == nil || IsNil(o.FactionId) {
		var ret int64
		return ret
	}
	return *o.FactionId
}

// GetFactionIdOk returns a tuple with the FactionId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SovereigntyMapGetInner) GetFactionIdOk() (*int64, bool) {
	if o == nil || IsNil(o.FactionId) {
		return nil, false
	}
	return o.FactionId, true
}

// HasFactionId returns a boolean if a field has been set.
func (o *SovereigntyMapGetInner) HasFactionId() bool {
	if o != nil && !IsNil(o.FactionId) {
		return true
	}

	return false
}

// SetFactionId gets a reference to the given int64 and assigns it to the FactionId field.
func (o *SovereigntyMapGetInner) SetFactionId(v int64) {
	o.FactionId = &v
}

// GetSystemId returns the SystemId field value
func (o *SovereigntyMapGetInner) GetSystemId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SystemId
}

// GetSystemIdOk returns a tuple with the SystemId field value
// and a boolean to check if the value has been set.
func (o *SovereigntyMapGetInner) GetSystemIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SystemId, true
}

// SetSystemId sets field value
func (o *SovereigntyMapGetInner) SetSystemId(v int64) {
	o.SystemId = v
}

func (o SovereigntyMapGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SovereigntyMapGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.AllianceId) {
		toSerialize["alliance_id"] = o.AllianceId
	}
	if !IsNil(o.CorporationId) {
		toSerialize["corporation_id"] = o.CorporationId
	}
	if !IsNil(o.FactionId) {
		toSerialize["faction_id"] = o.FactionId
	}
	toSerialize["system_id"] = o.SystemId
	return toSerialize, nil
}

func (o *SovereigntyMapGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"system_id",
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

	varSovereigntyMapGetInner := _SovereigntyMapGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varSovereigntyMapGetInner)

	if err != nil {
		return err
	}

	*o = SovereigntyMapGetInner(varSovereigntyMapGetInner)

	return err
}

type NullableSovereigntyMapGetInner struct {
	value *SovereigntyMapGetInner
	isSet bool
}

func (v NullableSovereigntyMapGetInner) Get() *SovereigntyMapGetInner {
	return v.value
}

func (v *NullableSovereigntyMapGetInner) Set(val *SovereigntyMapGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableSovereigntyMapGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableSovereigntyMapGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSovereigntyMapGetInner(val *SovereigntyMapGetInner) *NullableSovereigntyMapGetInner {
	return &NullableSovereigntyMapGetInner{value: val, isSet: true}
}

func (v NullableSovereigntyMapGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSovereigntyMapGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


