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

// checks if the FwLeaderboardsCorporationsGetKills type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwLeaderboardsCorporationsGetKills{}

// FwLeaderboardsCorporationsGetKills Top 10 rankings of corporations by number of kills from yesterday, last week and in total
type FwLeaderboardsCorporationsGetKills struct {
	// Top 10 ranking of corporations active in faction warfare by total kills. A corporation is considered \"active\" if they have participated in faction warfare in the past 14 days
	ActiveTotal []FwLeaderboardsCorporationsGetKillsActiveTotalInner `json:"active_total"`
	// Top 10 ranking of corporations by kills in the past week
	LastWeek []FwLeaderboardsCorporationsGetKillsLastWeekInner `json:"last_week"`
	// Top 10 ranking of corporations by kills in the past day
	Yesterday []FwLeaderboardsCorporationsGetKillsYesterdayInner `json:"yesterday"`
}

type _FwLeaderboardsCorporationsGetKills FwLeaderboardsCorporationsGetKills

// NewFwLeaderboardsCorporationsGetKills instantiates a new FwLeaderboardsCorporationsGetKills object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwLeaderboardsCorporationsGetKills(activeTotal []FwLeaderboardsCorporationsGetKillsActiveTotalInner, lastWeek []FwLeaderboardsCorporationsGetKillsLastWeekInner, yesterday []FwLeaderboardsCorporationsGetKillsYesterdayInner) *FwLeaderboardsCorporationsGetKills {
	this := FwLeaderboardsCorporationsGetKills{}
	this.ActiveTotal = activeTotal
	this.LastWeek = lastWeek
	this.Yesterday = yesterday
	return &this
}

// NewFwLeaderboardsCorporationsGetKillsWithDefaults instantiates a new FwLeaderboardsCorporationsGetKills object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwLeaderboardsCorporationsGetKillsWithDefaults() *FwLeaderboardsCorporationsGetKills {
	this := FwLeaderboardsCorporationsGetKills{}
	return &this
}

// GetActiveTotal returns the ActiveTotal field value
func (o *FwLeaderboardsCorporationsGetKills) GetActiveTotal() []FwLeaderboardsCorporationsGetKillsActiveTotalInner {
	if o == nil {
		var ret []FwLeaderboardsCorporationsGetKillsActiveTotalInner
		return ret
	}

	return o.ActiveTotal
}

// GetActiveTotalOk returns a tuple with the ActiveTotal field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCorporationsGetKills) GetActiveTotalOk() ([]FwLeaderboardsCorporationsGetKillsActiveTotalInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.ActiveTotal, true
}

// SetActiveTotal sets field value
func (o *FwLeaderboardsCorporationsGetKills) SetActiveTotal(v []FwLeaderboardsCorporationsGetKillsActiveTotalInner) {
	o.ActiveTotal = v
}

// GetLastWeek returns the LastWeek field value
func (o *FwLeaderboardsCorporationsGetKills) GetLastWeek() []FwLeaderboardsCorporationsGetKillsLastWeekInner {
	if o == nil {
		var ret []FwLeaderboardsCorporationsGetKillsLastWeekInner
		return ret
	}

	return o.LastWeek
}

// GetLastWeekOk returns a tuple with the LastWeek field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCorporationsGetKills) GetLastWeekOk() ([]FwLeaderboardsCorporationsGetKillsLastWeekInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.LastWeek, true
}

// SetLastWeek sets field value
func (o *FwLeaderboardsCorporationsGetKills) SetLastWeek(v []FwLeaderboardsCorporationsGetKillsLastWeekInner) {
	o.LastWeek = v
}

// GetYesterday returns the Yesterday field value
func (o *FwLeaderboardsCorporationsGetKills) GetYesterday() []FwLeaderboardsCorporationsGetKillsYesterdayInner {
	if o == nil {
		var ret []FwLeaderboardsCorporationsGetKillsYesterdayInner
		return ret
	}

	return o.Yesterday
}

// GetYesterdayOk returns a tuple with the Yesterday field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCorporationsGetKills) GetYesterdayOk() ([]FwLeaderboardsCorporationsGetKillsYesterdayInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Yesterday, true
}

// SetYesterday sets field value
func (o *FwLeaderboardsCorporationsGetKills) SetYesterday(v []FwLeaderboardsCorporationsGetKillsYesterdayInner) {
	o.Yesterday = v
}

func (o FwLeaderboardsCorporationsGetKills) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwLeaderboardsCorporationsGetKills) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["active_total"] = o.ActiveTotal
	toSerialize["last_week"] = o.LastWeek
	toSerialize["yesterday"] = o.Yesterday
	return toSerialize, nil
}

func (o *FwLeaderboardsCorporationsGetKills) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"active_total",
		"last_week",
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

	varFwLeaderboardsCorporationsGetKills := _FwLeaderboardsCorporationsGetKills{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varFwLeaderboardsCorporationsGetKills)

	if err != nil {
		return err
	}

	*o = FwLeaderboardsCorporationsGetKills(varFwLeaderboardsCorporationsGetKills)

	return err
}

type NullableFwLeaderboardsCorporationsGetKills struct {
	value *FwLeaderboardsCorporationsGetKills
	isSet bool
}

func (v NullableFwLeaderboardsCorporationsGetKills) Get() *FwLeaderboardsCorporationsGetKills {
	return v.value
}

func (v *NullableFwLeaderboardsCorporationsGetKills) Set(val *FwLeaderboardsCorporationsGetKills) {
	v.value = val
	v.isSet = true
}

func (v NullableFwLeaderboardsCorporationsGetKills) IsSet() bool {
	return v.isSet
}

func (v *NullableFwLeaderboardsCorporationsGetKills) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwLeaderboardsCorporationsGetKills(val *FwLeaderboardsCorporationsGetKills) *NullableFwLeaderboardsCorporationsGetKills {
	return &NullableFwLeaderboardsCorporationsGetKills{value: val, isSet: true}
}

func (v NullableFwLeaderboardsCorporationsGetKills) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwLeaderboardsCorporationsGetKills) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


