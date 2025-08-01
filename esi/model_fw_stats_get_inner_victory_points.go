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

// checks if the FwStatsGetInnerVictoryPoints type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwStatsGetInnerVictoryPoints{}

// FwStatsGetInnerVictoryPoints Summary of victory points gained for the given faction
type FwStatsGetInnerVictoryPoints struct {
	// Last week's victory points gained
	LastWeek int64 `json:"last_week"`
	// Total victory points gained since faction warfare began
	Total int64 `json:"total"`
	// Yesterday's victory points gained
	Yesterday int64 `json:"yesterday"`
}

type _FwStatsGetInnerVictoryPoints FwStatsGetInnerVictoryPoints

// NewFwStatsGetInnerVictoryPoints instantiates a new FwStatsGetInnerVictoryPoints object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwStatsGetInnerVictoryPoints(lastWeek int64, total int64, yesterday int64) *FwStatsGetInnerVictoryPoints {
	this := FwStatsGetInnerVictoryPoints{}
	this.LastWeek = lastWeek
	this.Total = total
	this.Yesterday = yesterday
	return &this
}

// NewFwStatsGetInnerVictoryPointsWithDefaults instantiates a new FwStatsGetInnerVictoryPoints object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwStatsGetInnerVictoryPointsWithDefaults() *FwStatsGetInnerVictoryPoints {
	this := FwStatsGetInnerVictoryPoints{}
	return &this
}

// GetLastWeek returns the LastWeek field value
func (o *FwStatsGetInnerVictoryPoints) GetLastWeek() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.LastWeek
}

// GetLastWeekOk returns a tuple with the LastWeek field value
// and a boolean to check if the value has been set.
func (o *FwStatsGetInnerVictoryPoints) GetLastWeekOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LastWeek, true
}

// SetLastWeek sets field value
func (o *FwStatsGetInnerVictoryPoints) SetLastWeek(v int64) {
	o.LastWeek = v
}

// GetTotal returns the Total field value
func (o *FwStatsGetInnerVictoryPoints) GetTotal() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Total
}

// GetTotalOk returns a tuple with the Total field value
// and a boolean to check if the value has been set.
func (o *FwStatsGetInnerVictoryPoints) GetTotalOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Total, true
}

// SetTotal sets field value
func (o *FwStatsGetInnerVictoryPoints) SetTotal(v int64) {
	o.Total = v
}

// GetYesterday returns the Yesterday field value
func (o *FwStatsGetInnerVictoryPoints) GetYesterday() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Yesterday
}

// GetYesterdayOk returns a tuple with the Yesterday field value
// and a boolean to check if the value has been set.
func (o *FwStatsGetInnerVictoryPoints) GetYesterdayOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Yesterday, true
}

// SetYesterday sets field value
func (o *FwStatsGetInnerVictoryPoints) SetYesterday(v int64) {
	o.Yesterday = v
}

func (o FwStatsGetInnerVictoryPoints) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwStatsGetInnerVictoryPoints) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["last_week"] = o.LastWeek
	toSerialize["total"] = o.Total
	toSerialize["yesterday"] = o.Yesterday
	return toSerialize, nil
}

func (o *FwStatsGetInnerVictoryPoints) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"last_week",
		"total",
		"yesterday",
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

	varFwStatsGetInnerVictoryPoints := _FwStatsGetInnerVictoryPoints{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varFwStatsGetInnerVictoryPoints)

	if err != nil {
		return err
	}

	*o = FwStatsGetInnerVictoryPoints(varFwStatsGetInnerVictoryPoints)

	return err
}

type NullableFwStatsGetInnerVictoryPoints struct {
	value *FwStatsGetInnerVictoryPoints
	isSet bool
}

func (v NullableFwStatsGetInnerVictoryPoints) Get() *FwStatsGetInnerVictoryPoints {
	return v.value
}

func (v *NullableFwStatsGetInnerVictoryPoints) Set(val *FwStatsGetInnerVictoryPoints) {
	v.value = val
	v.isSet = true
}

func (v NullableFwStatsGetInnerVictoryPoints) IsSet() bool {
	return v.isSet
}

func (v *NullableFwStatsGetInnerVictoryPoints) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwStatsGetInnerVictoryPoints(val *FwStatsGetInnerVictoryPoints) *NullableFwStatsGetInnerVictoryPoints {
	return &NullableFwStatsGetInnerVictoryPoints{value: val, isSet: true}
}

func (v NullableFwStatsGetInnerVictoryPoints) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwStatsGetInnerVictoryPoints) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


