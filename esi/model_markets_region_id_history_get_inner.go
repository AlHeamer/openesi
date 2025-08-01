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

// checks if the MarketsRegionIdHistoryGetInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &MarketsRegionIdHistoryGetInner{}

// MarketsRegionIdHistoryGetInner struct for MarketsRegionIdHistoryGetInner
type MarketsRegionIdHistoryGetInner struct {
	Average float64 `json:"average"`
	// The date of this historical statistic entry
	Date string `json:"date"`
	Highest float64 `json:"highest"`
	Lowest float64 `json:"lowest"`
	// Total number of orders happened that day
	OrderCount int64 `json:"order_count"`
	// Total
	Volume int64 `json:"volume"`
}

type _MarketsRegionIdHistoryGetInner MarketsRegionIdHistoryGetInner

// NewMarketsRegionIdHistoryGetInner instantiates a new MarketsRegionIdHistoryGetInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMarketsRegionIdHistoryGetInner(average float64, date string, highest float64, lowest float64, orderCount int64, volume int64) *MarketsRegionIdHistoryGetInner {
	this := MarketsRegionIdHistoryGetInner{}
	this.Average = average
	this.Date = date
	this.Highest = highest
	this.Lowest = lowest
	this.OrderCount = orderCount
	this.Volume = volume
	return &this
}

// NewMarketsRegionIdHistoryGetInnerWithDefaults instantiates a new MarketsRegionIdHistoryGetInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMarketsRegionIdHistoryGetInnerWithDefaults() *MarketsRegionIdHistoryGetInner {
	this := MarketsRegionIdHistoryGetInner{}
	return &this
}

// GetAverage returns the Average field value
func (o *MarketsRegionIdHistoryGetInner) GetAverage() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Average
}

// GetAverageOk returns a tuple with the Average field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetAverageOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Average, true
}

// SetAverage sets field value
func (o *MarketsRegionIdHistoryGetInner) SetAverage(v float64) {
	o.Average = v
}

// GetDate returns the Date field value
func (o *MarketsRegionIdHistoryGetInner) GetDate() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Date
}

// GetDateOk returns a tuple with the Date field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetDateOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Date, true
}

// SetDate sets field value
func (o *MarketsRegionIdHistoryGetInner) SetDate(v string) {
	o.Date = v
}

// GetHighest returns the Highest field value
func (o *MarketsRegionIdHistoryGetInner) GetHighest() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Highest
}

// GetHighestOk returns a tuple with the Highest field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetHighestOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Highest, true
}

// SetHighest sets field value
func (o *MarketsRegionIdHistoryGetInner) SetHighest(v float64) {
	o.Highest = v
}

// GetLowest returns the Lowest field value
func (o *MarketsRegionIdHistoryGetInner) GetLowest() float64 {
	if o == nil {
		var ret float64
		return ret
	}

	return o.Lowest
}

// GetLowestOk returns a tuple with the Lowest field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetLowestOk() (*float64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Lowest, true
}

// SetLowest sets field value
func (o *MarketsRegionIdHistoryGetInner) SetLowest(v float64) {
	o.Lowest = v
}

// GetOrderCount returns the OrderCount field value
func (o *MarketsRegionIdHistoryGetInner) GetOrderCount() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.OrderCount
}

// GetOrderCountOk returns a tuple with the OrderCount field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetOrderCountOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.OrderCount, true
}

// SetOrderCount sets field value
func (o *MarketsRegionIdHistoryGetInner) SetOrderCount(v int64) {
	o.OrderCount = v
}

// GetVolume returns the Volume field value
func (o *MarketsRegionIdHistoryGetInner) GetVolume() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Volume
}

// GetVolumeOk returns a tuple with the Volume field value
// and a boolean to check if the value has been set.
func (o *MarketsRegionIdHistoryGetInner) GetVolumeOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Volume, true
}

// SetVolume sets field value
func (o *MarketsRegionIdHistoryGetInner) SetVolume(v int64) {
	o.Volume = v
}

func (o MarketsRegionIdHistoryGetInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o MarketsRegionIdHistoryGetInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["average"] = o.Average
	toSerialize["date"] = o.Date
	toSerialize["highest"] = o.Highest
	toSerialize["lowest"] = o.Lowest
	toSerialize["order_count"] = o.OrderCount
	toSerialize["volume"] = o.Volume
	return toSerialize, nil
}

func (o *MarketsRegionIdHistoryGetInner) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"average",
		"date",
		"highest",
		"lowest",
		"order_count",
		"volume",
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

	varMarketsRegionIdHistoryGetInner := _MarketsRegionIdHistoryGetInner{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varMarketsRegionIdHistoryGetInner)

	if err != nil {
		return err
	}

	*o = MarketsRegionIdHistoryGetInner(varMarketsRegionIdHistoryGetInner)

	return err
}

type NullableMarketsRegionIdHistoryGetInner struct {
	value *MarketsRegionIdHistoryGetInner
	isSet bool
}

func (v NullableMarketsRegionIdHistoryGetInner) Get() *MarketsRegionIdHistoryGetInner {
	return v.value
}

func (v *NullableMarketsRegionIdHistoryGetInner) Set(val *MarketsRegionIdHistoryGetInner) {
	v.value = val
	v.isSet = true
}

func (v NullableMarketsRegionIdHistoryGetInner) IsSet() bool {
	return v.isSet
}

func (v *NullableMarketsRegionIdHistoryGetInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMarketsRegionIdHistoryGetInner(val *MarketsRegionIdHistoryGetInner) *NullableMarketsRegionIdHistoryGetInner {
	return &NullableMarketsRegionIdHistoryGetInner{value: val, isSet: true}
}

func (v NullableMarketsRegionIdHistoryGetInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMarketsRegionIdHistoryGetInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


