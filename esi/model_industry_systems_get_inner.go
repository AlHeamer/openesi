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

// checks if the IndustrySystemsGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &IndustrySystemsGetInner{}

// IndustrySystemsGetInner struct for IndustrySystemsGetInner
type IndustrySystemsGetInner struct {
	CostIndices []IndustrySystemsGetInnerCostIndicesInner `json:"cost_indices"`
	SolarSystemId int64 `json:"solar_system_id"`
}

type _IndustrySystemsGetInner IndustrySystemsGetInner

// NewIndustrySystemsGetInner instantiates a new IndustrySystemsGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIndustrySystemsGetInner(costIndices []IndustrySystemsGetInnerCostIndicesInner, solarSystemId int64) *IndustrySystemsGetInner {
	this := IndustrySystemsGetInner{}
	this.CostIndices = costIndices
	this.SolarSystemId = solarSystemId
	return &this
}

// NewIndustrySystemsGetInnerWithDefaults instantiates a new IndustrySystemsGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIndustrySystemsGetInnerWithDefaults() *IndustrySystemsGetInner {
	this := IndustrySystemsGetInner{}
	return &this
}

// GetCostIndices returns the CostIndices field value
func (o *IndustrySystemsGetInner) GetCostIndices() []IndustrySystemsGetInnerCostIndicesInner {
	if o == nil {
		var ret []IndustrySystemsGetInnerCostIndicesInner
		return ret
	}

	return o.CostIndices
}

// GetCostIndicesOk returns a tuple with the CostIndices field value
// and a boolean to check if the value has been set.
func (o *IndustrySystemsGetInner) GetCostIndicesOk() ([]IndustrySystemsGetInnerCostIndicesInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.CostIndices, true
}

// SetCostIndices sets field value
func (o *IndustrySystemsGetInner) SetCostIndices(v []IndustrySystemsGetInnerCostIndicesInner) {
	o.CostIndices = v
}

// GetSolarSystemId returns the SolarSystemId field value
func (o *IndustrySystemsGetInner) GetSolarSystemId() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.SolarSystemId
}

// GetSolarSystemIdOk returns a tuple with the SolarSystemId field value
// and a boolean to check if the value has been set.
func (o *IndustrySystemsGetInner) GetSolarSystemIdOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SolarSystemId, true
}

// SetSolarSystemId sets field value
func (o *IndustrySystemsGetInner) SetSolarSystemId(v int64) {
	o.SolarSystemId = v
}

func (o IndustrySystemsGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o IndustrySystemsGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["cost_indices"] = o.CostIndices
	toSerialize["solar_system_id"] = o.SolarSystemId
	return toSerialize, nil
}

func (o *IndustrySystemsGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"cost_indices",
		"solar_system_id",
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

	varIndustrySystemsGetInner := _IndustrySystemsGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varIndustrySystemsGetInner)

	if err != nil {
		return err
	}

	*o = IndustrySystemsGetInner(varIndustrySystemsGetInner)

	return err
}

type NullableIndustrySystemsGetInner struct {
	value *IndustrySystemsGetInner
	isSet bool
}

func (v NullableIndustrySystemsGetInner) Get() *IndustrySystemsGetInner {
	return v.value
}

func (v *NullableIndustrySystemsGetInner) Set(val *IndustrySystemsGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableIndustrySystemsGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableIndustrySystemsGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIndustrySystemsGetInner(val *IndustrySystemsGetInner) *NullableIndustrySystemsGetInner {
	return &NullableIndustrySystemsGetInner{value: val, isSet: true}
}

func (v NullableIndustrySystemsGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIndustrySystemsGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


