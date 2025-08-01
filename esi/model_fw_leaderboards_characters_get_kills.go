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

// checks if the FwLeaderboardsCharactersGetKills type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FwLeaderboardsCharactersGetKills{}

// FwLeaderboardsCharactersGetKills Top 100 rankings of pilots by number of kills from yesterday, last week and in total
type FwLeaderboardsCharactersGetKills struct {
	// Top 100 ranking of pilots active in faction warfare by total kills. A pilot is considered \"active\" if they have participated in faction warfare in the past 14 days
	ActiveTotal []FwLeaderboardsCharactersGetKillsActiveTotalInner `json:"active_total"`
	// Top 100 ranking of pilots by kills in the past week
	LastWeek []FwLeaderboardsCharactersGetKillsLastWeekInner `json:"last_week"`
	// Top 100 ranking of pilots by kills in the past day
	Yesterday []FwLeaderboardsCharactersGetKillsYesterdayInner `json:"yesterday"`
}

type _FwLeaderboardsCharactersGetKills FwLeaderboardsCharactersGetKills

// NewFwLeaderboardsCharactersGetKills instantiates a new FwLeaderboardsCharactersGetKills object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFwLeaderboardsCharactersGetKills(activeTotal []FwLeaderboardsCharactersGetKillsActiveTotalInner, lastWeek []FwLeaderboardsCharactersGetKillsLastWeekInner, yesterday []FwLeaderboardsCharactersGetKillsYesterdayInner) *FwLeaderboardsCharactersGetKills {
	this := FwLeaderboardsCharactersGetKills{}
	this.ActiveTotal = activeTotal
	this.LastWeek = lastWeek
	this.Yesterday = yesterday
	return &this
}

// NewFwLeaderboardsCharactersGetKillsWithDefaults instantiates a new FwLeaderboardsCharactersGetKills object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFwLeaderboardsCharactersGetKillsWithDefaults() *FwLeaderboardsCharactersGetKills {
	this := FwLeaderboardsCharactersGetKills{}
	return &this
}

// GetActiveTotal returns the ActiveTotal field value
func (o *FwLeaderboardsCharactersGetKills) GetActiveTotal() []FwLeaderboardsCharactersGetKillsActiveTotalInner {
	if o == nil {
		var ret []FwLeaderboardsCharactersGetKillsActiveTotalInner
		return ret
	}

	return o.ActiveTotal
}

// GetActiveTotalOk returns a tuple with the ActiveTotal field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCharactersGetKills) GetActiveTotalOk() ([]FwLeaderboardsCharactersGetKillsActiveTotalInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.ActiveTotal, true
}

// SetActiveTotal sets field value
func (o *FwLeaderboardsCharactersGetKills) SetActiveTotal(v []FwLeaderboardsCharactersGetKillsActiveTotalInner) {
	o.ActiveTotal = v
}

// GetLastWeek returns the LastWeek field value
func (o *FwLeaderboardsCharactersGetKills) GetLastWeek() []FwLeaderboardsCharactersGetKillsLastWeekInner {
	if o == nil {
		var ret []FwLeaderboardsCharactersGetKillsLastWeekInner
		return ret
	}

	return o.LastWeek
}

// GetLastWeekOk returns a tuple with the LastWeek field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCharactersGetKills) GetLastWeekOk() ([]FwLeaderboardsCharactersGetKillsLastWeekInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.LastWeek, true
}

// SetLastWeek sets field value
func (o *FwLeaderboardsCharactersGetKills) SetLastWeek(v []FwLeaderboardsCharactersGetKillsLastWeekInner) {
	o.LastWeek = v
}

// GetYesterday returns the Yesterday field value
func (o *FwLeaderboardsCharactersGetKills) GetYesterday() []FwLeaderboardsCharactersGetKillsYesterdayInner {
	if o == nil {
		var ret []FwLeaderboardsCharactersGetKillsYesterdayInner
		return ret
	}

	return o.Yesterday
}

// GetYesterdayOk returns a tuple with the Yesterday field value
// and a boolean to check if the value has been set.
func (o *FwLeaderboardsCharactersGetKills) GetYesterdayOk() ([]FwLeaderboardsCharactersGetKillsYesterdayInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Yesterday, true
}

// SetYesterday sets field value
func (o *FwLeaderboardsCharactersGetKills) SetYesterday(v []FwLeaderboardsCharactersGetKillsYesterdayInner) {
	o.Yesterday = v
}

func (o FwLeaderboardsCharactersGetKills) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FwLeaderboardsCharactersGetKills) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["active_total"] = o.ActiveTotal
	toSerialize["last_week"] = o.LastWeek
	toSerialize["yesterday"] = o.Yesterday
	return toSerialize, nil
}

func (o *FwLeaderboardsCharactersGetKills) UnmarshalJSON(data []byte) (err error) {
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

	varFwLeaderboardsCharactersGetKills := _FwLeaderboardsCharactersGetKills{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varFwLeaderboardsCharactersGetKills)

	if err != nil {
		return err
	}

	*o = FwLeaderboardsCharactersGetKills(varFwLeaderboardsCharactersGetKills)

	return err
}

type NullableFwLeaderboardsCharactersGetKills struct {
	value *FwLeaderboardsCharactersGetKills
	isSet bool
}

func (v NullableFwLeaderboardsCharactersGetKills) Get() *FwLeaderboardsCharactersGetKills {
	return v.value
}

func (v *NullableFwLeaderboardsCharactersGetKills) Set(val *FwLeaderboardsCharactersGetKills) {
	v.value = val
	v.isSet = true
}

func (v NullableFwLeaderboardsCharactersGetKills) IsSet() bool {
	return v.isSet
}

func (v *NullableFwLeaderboardsCharactersGetKills) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFwLeaderboardsCharactersGetKills(val *FwLeaderboardsCharactersGetKills) *NullableFwLeaderboardsCharactersGetKills {
	return &NullableFwLeaderboardsCharactersGetKills{value: val, isSet: true}
}

func (v NullableFwLeaderboardsCharactersGetKills) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFwLeaderboardsCharactersGetKills) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


