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

// checks if the CorporationsCorporationIdFwStatsGetVictoryPoints type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CorporationsCorporationIdFwStatsGetVictoryPoints{}

// CorporationsCorporationIdFwStatsGetVictoryPoints Summary of victory points gained by the given corporation for the enlisted faction
type CorporationsCorporationIdFwStatsGetVictoryPoints struct {
	// Last week's victory points gained by members of the given corporation
	LastWeek int64 `json:"last_week"`
	// Total victory points gained since the given corporation enlisted
	Total int64 `json:"total"`
	// Yesterday's victory points gained by members of the given corporation
	Yesterday int64 `json:"yesterday"`
}

type _CorporationsCorporationIdFwStatsGetVictoryPoints CorporationsCorporationIdFwStatsGetVictoryPoints

// NewCorporationsCorporationIdFwStatsGetVictoryPoints instantiates a new CorporationsCorporationIdFwStatsGetVictoryPoints object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCorporationsCorporationIdFwStatsGetVictoryPoints(lastWeek int64, total int64, yesterday int64) *CorporationsCorporationIdFwStatsGetVictoryPoints {
	this := CorporationsCorporationIdFwStatsGetVictoryPoints{}
	this.LastWeek = lastWeek
	this.Total = total
	this.Yesterday = yesterday
	return &this
}

// NewCorporationsCorporationIdFwStatsGetVictoryPointsWithDefaults instantiates a new CorporationsCorporationIdFwStatsGetVictoryPoints object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCorporationsCorporationIdFwStatsGetVictoryPointsWithDefaults() *CorporationsCorporationIdFwStatsGetVictoryPoints {
	this := CorporationsCorporationIdFwStatsGetVictoryPoints{}
	return &this
}

// GetLastWeek returns the LastWeek field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetLastWeek() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.LastWeek
}

// GetLastWeekOk returns a tuple with the LastWeek field value
// and a boolean to check if the value has been set.
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetLastWeekOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LastWeek, true
}

// SetLastWeek sets field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) SetLastWeek(v int64) {
	o.LastWeek = v
}

// GetTotal returns the Total field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetTotal() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Total
}

// GetTotalOk returns a tuple with the Total field value
// and a boolean to check if the value has been set.
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetTotalOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Total, true
}

// SetTotal sets field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) SetTotal(v int64) {
	o.Total = v
}

// GetYesterday returns the Yesterday field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetYesterday() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Yesterday
}

// GetYesterdayOk returns a tuple with the Yesterday field value
// and a boolean to check if the value has been set.
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) GetYesterdayOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Yesterday, true
}

// SetYesterday sets field value
func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) SetYesterday(v int64) {
	o.Yesterday = v
}

func (o CorporationsCorporationIdFwStatsGetVictoryPoints) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CorporationsCorporationIdFwStatsGetVictoryPoints) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["last_week"] = o.LastWeek
	toSerialize["total"] = o.Total
	toSerialize["yesterday"] = o.Yesterday
	return toSerialize, nil
}

func (o *CorporationsCorporationIdFwStatsGetVictoryPoints) UnmarshalJSON(data []byte) (err error) {
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

	varCorporationsCorporationIdFwStatsGetVictoryPoints := _CorporationsCorporationIdFwStatsGetVictoryPoints{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCorporationsCorporationIdFwStatsGetVictoryPoints)

	if err != nil {
		return err
	}

	*o = CorporationsCorporationIdFwStatsGetVictoryPoints(varCorporationsCorporationIdFwStatsGetVictoryPoints)

	return err
}

type NullableCorporationsCorporationIdFwStatsGetVictoryPoints struct {
	value *CorporationsCorporationIdFwStatsGetVictoryPoints
	isSet bool
}

func (v NullableCorporationsCorporationIdFwStatsGetVictoryPoints) Get() *CorporationsCorporationIdFwStatsGetVictoryPoints {
	return v.value
}

func (v *NullableCorporationsCorporationIdFwStatsGetVictoryPoints) Set(val *CorporationsCorporationIdFwStatsGetVictoryPoints) {
	v.value = val
	v.isSet = true
}

func (v NullableCorporationsCorporationIdFwStatsGetVictoryPoints) IsSet() bool {
	return v.isSet
}

func (v *NullableCorporationsCorporationIdFwStatsGetVictoryPoints) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCorporationsCorporationIdFwStatsGetVictoryPoints(val *CorporationsCorporationIdFwStatsGetVictoryPoints) *NullableCorporationsCorporationIdFwStatsGetVictoryPoints {
	return &NullableCorporationsCorporationIdFwStatsGetVictoryPoints{value: val, isSet: true}
}

func (v NullableCorporationsCorporationIdFwStatsGetVictoryPoints) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCorporationsCorporationIdFwStatsGetVictoryPoints) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


