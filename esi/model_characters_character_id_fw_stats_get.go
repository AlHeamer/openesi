/*
EVE Stellar Information (ESI) - tranquility

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2020-01-01
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package esi

import (
	"encoding/json"
	"time"
	"bytes"
	"fmt"
)

// checks if the CharactersCharacterIdFwStatsGet type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CharactersCharacterIdFwStatsGet{}

// CharactersCharacterIdFwStatsGet struct for CharactersCharacterIdFwStatsGet
type CharactersCharacterIdFwStatsGet struct {
	// The given character's current faction rank
	CurrentRank *int64 `json:"current_rank,omitempty"`
	// The enlistment date of the given character into faction warfare. Will not be included if character is not enlisted in faction warfare
	EnlistedOn *time.Time `json:"enlisted_on,omitempty"`
	// The faction the given character is enlisted to fight for. Will not be included if character is not enlisted in faction warfare
	FactionId *int64 `json:"faction_id,omitempty"`
	// The given character's highest faction rank achieved
	HighestRank *int64 `json:"highest_rank,omitempty"`
	Kills CharactersCharacterIdFwStatsGetKills `json:"kills"`
	VictoryPoints CharactersCharacterIdFwStatsGetVictoryPoints `json:"victory_points"`
}

type _CharactersCharacterIdFwStatsGet CharactersCharacterIdFwStatsGet

// NewCharactersCharacterIdFwStatsGet instantiates a new CharactersCharacterIdFwStatsGet object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCharactersCharacterIdFwStatsGet(kills CharactersCharacterIdFwStatsGetKills, victoryPoints CharactersCharacterIdFwStatsGetVictoryPoints) *CharactersCharacterIdFwStatsGet {
	this := CharactersCharacterIdFwStatsGet{}
	this.Kills = kills
	this.VictoryPoints = victoryPoints
	return &this
}

// NewCharactersCharacterIdFwStatsGetWithDefaults instantiates a new CharactersCharacterIdFwStatsGet object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCharactersCharacterIdFwStatsGetWithDefaults() *CharactersCharacterIdFwStatsGet {
	this := CharactersCharacterIdFwStatsGet{}
	return &this
}

// GetCurrentRank returns the CurrentRank field value if set, zero value otherwise.
func (o *CharactersCharacterIdFwStatsGet) GetCurrentRank() int64 {
	if o == nil || IsNil(o.CurrentRank) {
		var ret int64
		return ret
	}
	return *o.CurrentRank
}

// GetCurrentRankOk returns a tuple with the CurrentRank field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetCurrentRankOk() (*int64, bool) {
	if o == nil || IsNil(o.CurrentRank) {
		return nil, false
	}
	return o.CurrentRank, true
}

// HasCurrentRank returns a boolean if a field has been set.
func (o *CharactersCharacterIdFwStatsGet) HasCurrentRank() bool {
	if o != nil && !IsNil(o.CurrentRank) {
		return true
	}

	return false
}

// SetCurrentRank gets a reference to the given int64 and assigns it to the CurrentRank field.
func (o *CharactersCharacterIdFwStatsGet) SetCurrentRank(v int64) {
	o.CurrentRank = &v
}

// GetEnlistedOn returns the EnlistedOn field value if set, zero value otherwise.
func (o *CharactersCharacterIdFwStatsGet) GetEnlistedOn() time.Time {
	if o == nil || IsNil(o.EnlistedOn) {
		var ret time.Time
		return ret
	}
	return *o.EnlistedOn
}

// GetEnlistedOnOk returns a tuple with the EnlistedOn field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetEnlistedOnOk() (*time.Time, bool) {
	if o == nil || IsNil(o.EnlistedOn) {
		return nil, false
	}
	return o.EnlistedOn, true
}

// HasEnlistedOn returns a boolean if a field has been set.
func (o *CharactersCharacterIdFwStatsGet) HasEnlistedOn() bool {
	if o != nil && !IsNil(o.EnlistedOn) {
		return true
	}

	return false
}

// SetEnlistedOn gets a reference to the given time.Time and assigns it to the EnlistedOn field.
func (o *CharactersCharacterIdFwStatsGet) SetEnlistedOn(v time.Time) {
	o.EnlistedOn = &v
}

// GetFactionId returns the FactionId field value if set, zero value otherwise.
func (o *CharactersCharacterIdFwStatsGet) GetFactionId() int64 {
	if o == nil || IsNil(o.FactionId) {
		var ret int64
		return ret
	}
	return *o.FactionId
}

// GetFactionIdOk returns a tuple with the FactionId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetFactionIdOk() (*int64, bool) {
	if o == nil || IsNil(o.FactionId) {
		return nil, false
	}
	return o.FactionId, true
}

// HasFactionId returns a boolean if a field has been set.
func (o *CharactersCharacterIdFwStatsGet) HasFactionId() bool {
	if o != nil && !IsNil(o.FactionId) {
		return true
	}

	return false
}

// SetFactionId gets a reference to the given int64 and assigns it to the FactionId field.
func (o *CharactersCharacterIdFwStatsGet) SetFactionId(v int64) {
	o.FactionId = &v
}

// GetHighestRank returns the HighestRank field value if set, zero value otherwise.
func (o *CharactersCharacterIdFwStatsGet) GetHighestRank() int64 {
	if o == nil || IsNil(o.HighestRank) {
		var ret int64
		return ret
	}
	return *o.HighestRank
}

// GetHighestRankOk returns a tuple with the HighestRank field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetHighestRankOk() (*int64, bool) {
	if o == nil || IsNil(o.HighestRank) {
		return nil, false
	}
	return o.HighestRank, true
}

// HasHighestRank returns a boolean if a field has been set.
func (o *CharactersCharacterIdFwStatsGet) HasHighestRank() bool {
	if o != nil && !IsNil(o.HighestRank) {
		return true
	}

	return false
}

// SetHighestRank gets a reference to the given int64 and assigns it to the HighestRank field.
func (o *CharactersCharacterIdFwStatsGet) SetHighestRank(v int64) {
	o.HighestRank = &v
}

// GetKills returns the Kills field value
func (o *CharactersCharacterIdFwStatsGet) GetKills() CharactersCharacterIdFwStatsGetKills {
	if o == nil {
		var ret CharactersCharacterIdFwStatsGetKills
		return ret
	}

	return o.Kills
}

// GetKillsOk returns a tuple with the Kills field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetKillsOk() (*CharactersCharacterIdFwStatsGetKills, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Kills, true
}

// SetKills sets field value
func (o *CharactersCharacterIdFwStatsGet) SetKills(v CharactersCharacterIdFwStatsGetKills) {
	o.Kills = v
}

// GetVictoryPoints returns the VictoryPoints field value
func (o *CharactersCharacterIdFwStatsGet) GetVictoryPoints() CharactersCharacterIdFwStatsGetVictoryPoints {
	if o == nil {
		var ret CharactersCharacterIdFwStatsGetVictoryPoints
		return ret
	}

	return o.VictoryPoints
}

// GetVictoryPointsOk returns a tuple with the VictoryPoints field value
// and a boolean to check if the value has been set.
func (o *CharactersCharacterIdFwStatsGet) GetVictoryPointsOk() (*CharactersCharacterIdFwStatsGetVictoryPoints, bool) {
	if o == nil {
		return nil, false
	}
	return &o.VictoryPoints, true
}

// SetVictoryPoints sets field value
func (o *CharactersCharacterIdFwStatsGet) SetVictoryPoints(v CharactersCharacterIdFwStatsGetVictoryPoints) {
	o.VictoryPoints = v
}

func (o CharactersCharacterIdFwStatsGet) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CharactersCharacterIdFwStatsGet) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.CurrentRank) {
		toSerialize["current_rank"] = o.CurrentRank
	}
	if !IsNil(o.EnlistedOn) {
		toSerialize["enlisted_on"] = o.EnlistedOn
	}
	if !IsNil(o.FactionId) {
		toSerialize["faction_id"] = o.FactionId
	}
	if !IsNil(o.HighestRank) {
		toSerialize["highest_rank"] = o.HighestRank
	}
	toSerialize["kills"] = o.Kills
	toSerialize["victory_points"] = o.VictoryPoints
	return toSerialize, nil
}

func (o *CharactersCharacterIdFwStatsGet) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"kills",
		"victory_points",
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

	varCharactersCharacterIdFwStatsGet := _CharactersCharacterIdFwStatsGet{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCharactersCharacterIdFwStatsGet)

	if err != nil {
		return err
	}

	*o = CharactersCharacterIdFwStatsGet(varCharactersCharacterIdFwStatsGet)

	return err
}

type NullableCharactersCharacterIdFwStatsGet struct {
	value *CharactersCharacterIdFwStatsGet
	isSet bool
}

func (v NullableCharactersCharacterIdFwStatsGet) Get() *CharactersCharacterIdFwStatsGet {
	return v.value
}

func (v *NullableCharactersCharacterIdFwStatsGet) Set(val *CharactersCharacterIdFwStatsGet) {
	v.value = val
	v.isSet = true
}

func (v NullableCharactersCharacterIdFwStatsGet) IsSet() bool {
	return v.isSet
}

func (v *NullableCharactersCharacterIdFwStatsGet) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCharactersCharacterIdFwStatsGet(val *CharactersCharacterIdFwStatsGet) *NullableCharactersCharacterIdFwStatsGet {
	return &NullableCharactersCharacterIdFwStatsGet{value: val, isSet: true}
}

func (v NullableCharactersCharacterIdFwStatsGet) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCharactersCharacterIdFwStatsGet) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


